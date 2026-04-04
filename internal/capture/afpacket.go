//go:build linux

package capture

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

// AFPacketEngine captures packets using Linux AF_PACKET for higher performance.
type AFPacketEngine struct {
	handle *afpacket.TPacket
	iface  string
	filter string
	output chan<- PacketData
	stats  Stats
}

// NewAFPacketEngine creates an AF_PACKET capture engine.
func NewAFPacketEngine(iface string, filter string, output chan<- PacketData) *AFPacketEngine {
	return &AFPacketEngine{
		iface:  iface,
		filter: filter,
		output: output,
	}
}

// Start begins capturing via AF_PACKET. Blocks until context is cancelled.
func (e *AFPacketEngine) Start(ctx context.Context) error {
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(e.iface),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(65536*128),
		afpacket.OptNumBlocks(8),
	)
	if err != nil {
		return fmt.Errorf("opening AF_PACKET on %s: %w", e.iface, err)
	}
	e.handle = handle
	defer handle.Close()

	if e.filter != "" {
		// Note: gopacket's AF_PACKET TPacket does not support BPF filters directly.
		// Filter must be applied at the application level, or users should use the
		// libpcap backend when BPF filters are needed.
		return fmt.Errorf("BPF filters are not supported with the afpacket backend; use --backend libpcap")
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packetSource.Lazy = true
	packetSource.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				continue
			}

			pd := PacketData{
				Data:        packet.Data(),
				CaptureInfo: packet.Metadata().CaptureInfo,
			}

			select {
			case e.output <- pd:
			default:
				atomic.AddUint64(&e.stats.AppDropped, 1)
			}
		}
	}
}

// GetStats returns AF_PACKET capture statistics.
func (e *AFPacketEngine) GetStats() Stats {
	if e.handle != nil {
		_, s, err := e.handle.SocketStats()
		if err == nil {
			atomic.StoreUint64(&e.stats.PacketsReceived, uint64(s.Packets()))
			atomic.StoreUint64(&e.stats.PacketsDropped, uint64(s.Drops()))
		}
	}
	return Stats{
		PacketsReceived: atomic.LoadUint64(&e.stats.PacketsReceived),
		PacketsDropped:  atomic.LoadUint64(&e.stats.PacketsDropped),
		AppDropped:      atomic.LoadUint64(&e.stats.AppDropped),
	}
}
