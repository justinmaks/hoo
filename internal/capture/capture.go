package capture

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	defaultSnapLen = 65536
	defaultTimeout = 100 * time.Millisecond
)

// PacketData is the unit of data passed from capture to decode.
type PacketData struct {
	Data      []byte
	CaptureInfo gopacket.CaptureInfo
}

// Stats holds capture statistics.
type Stats struct {
	PacketsReceived  uint64
	PacketsDropped   uint64 // kernel drops
	PacketsIfDropped uint64 // interface drops
	AppDropped       uint64 // channel overflow drops
}

// CaptureEngine is the interface for packet capture backends.
type CaptureEngine interface {
	Start(ctx context.Context) error
	GetStats() Stats
}

// Engine manages packet capture from a network interface.
type Engine struct {
	handle   *pcap.Handle
	iface    string
	filter   string
	snapLen  int32
	output   chan<- PacketData
	stats    Stats
	stopFunc context.CancelFunc
}

// NewEngine creates a capture engine for the given interface.
func NewEngine(iface string, filter string, output chan<- PacketData) *Engine {
	return &Engine{
		iface:   iface,
		filter:  filter,
		snapLen: defaultSnapLen,
		output:  output,
	}
}

// Start begins capturing packets. Blocks until context is cancelled.
func (e *Engine) Start(ctx context.Context) error {
	handle, err := pcap.OpenLive(e.iface, e.snapLen, true, defaultTimeout)
	if err != nil {
		return fmt.Errorf("opening interface %s: %w\n\nMake sure you have sufficient privileges. See: hoo --help", e.iface, err)
	}
	e.handle = handle

	if e.filter != "" {
		if err := handle.SetBPFFilter(e.filter); err != nil {
			handle.Close()
			return fmt.Errorf("invalid BPF filter %q: %w", e.filter, err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			e.updateKernelStats()
			handle.Close()
			return nil
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				// Timeout or temporary error — just continue.
				continue
			}

			pd := PacketData{
				Data:        packet.Data(),
				CaptureInfo: packet.Metadata().CaptureInfo,
			}

			select {
			case e.output <- pd:
			default:
				// Channel full — drop packet and count it.
				atomic.AddUint64(&e.stats.AppDropped, 1)
			}
		}
	}
}

// GetStats returns current capture statistics.
func (e *Engine) GetStats() Stats {
	e.updateKernelStats()
	return Stats{
		PacketsReceived:  atomic.LoadUint64(&e.stats.PacketsReceived),
		PacketsDropped:   atomic.LoadUint64(&e.stats.PacketsDropped),
		PacketsIfDropped: atomic.LoadUint64(&e.stats.PacketsIfDropped),
		AppDropped:       atomic.LoadUint64(&e.stats.AppDropped),
	}
}

func (e *Engine) updateKernelStats() {
	if e.handle == nil {
		return
	}
	stats, err := e.handle.Stats()
	if err != nil {
		return
	}
	atomic.StoreUint64(&e.stats.PacketsReceived, uint64(stats.PacketsReceived))
	atomic.StoreUint64(&e.stats.PacketsDropped, uint64(stats.PacketsDropped))
	atomic.StoreUint64(&e.stats.PacketsIfDropped, uint64(stats.PacketsIfDropped))
}
