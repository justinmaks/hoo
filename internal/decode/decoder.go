package decode

import (
	"net"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/justinmaks/hoo/internal/capture"
)

// Direction indicates traffic direction relative to the capture interface.
type Direction int

const (
	DirectionUnknown  Direction = iota
	DirectionInbound
	DirectionOutbound
)

// DecodedPacket holds parsed information from a raw packet.
type DecodedPacket struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  Protocol
	Transport string // "TCP", "UDP", "ICMP"
	TCPFlags  TCPFlags
	Length    int
	Direction Direction
	Timestamp int64 // unix nano
}

// TCPFlags holds parsed TCP flag bits.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
}

// Decoder parses raw packet data into structured DecodedPacket values.
type Decoder struct {
	localIPs    map[string]bool
	errorCount  uint64
	dirFilter   string // "inbound", "outbound", "both"

	// Reusable parser to avoid allocations.
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp    layers.ICMPv4
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

// NewDecoder creates a decoder that knows the local interface IPs for direction detection.
func NewDecoder(localIPs []net.IP, dirFilter string) *Decoder {
	d := &Decoder{
		localIPs:  make(map[string]bool),
		dirFilter: dirFilter,
		decoded:   make([]gopacket.LayerType, 0, 4),
	}

	for _, ip := range localIPs {
		d.localIPs[ip.String()] = true
	}

	d.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&d.eth, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp,
	)
	d.parser.IgnoreUnsupported = true

	return d
}

// Decode parses a PacketData into a DecodedPacket.
// Returns nil if the packet cannot be decoded or is filtered out.
func (d *Decoder) Decode(pd capture.PacketData) *DecodedPacket {
	d.decoded = d.decoded[:0]
	if err := d.parser.DecodeLayers(pd.Data, &d.decoded); err != nil {
		// Some layers may still have decoded successfully, so continue.
	}

	pkt := &DecodedPacket{
		Length:    len(pd.Data),
		Timestamp: pd.CaptureInfo.Timestamp.UnixNano(),
	}

	hasNetwork := false
	hasTransport := false

	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			pkt.SrcIP = d.ip4.SrcIP
			pkt.DstIP = d.ip4.DstIP
			hasNetwork = true
		case layers.LayerTypeIPv6:
			pkt.SrcIP = d.ip6.SrcIP
			pkt.DstIP = d.ip6.DstIP
			hasNetwork = true
		case layers.LayerTypeTCP:
			pkt.SrcPort = uint16(d.tcp.SrcPort)
			pkt.DstPort = uint16(d.tcp.DstPort)
			pkt.Transport = "TCP"
			pkt.TCPFlags = TCPFlags{
				SYN: d.tcp.SYN,
				ACK: d.tcp.ACK,
				FIN: d.tcp.FIN,
				RST: d.tcp.RST,
				PSH: d.tcp.PSH,
			}
			hasTransport = true
		case layers.LayerTypeUDP:
			pkt.SrcPort = uint16(d.udp.SrcPort)
			pkt.DstPort = uint16(d.udp.DstPort)
			pkt.Transport = "UDP"
			hasTransport = true
		case layers.LayerTypeICMPv4:
			pkt.Transport = "ICMP"
			hasTransport = true
		}
	}

	if !hasNetwork {
		atomic.AddUint64(&d.errorCount, 1)
		return nil
	}

	// Determine direction.
	if d.localIPs[pkt.DstIP.String()] {
		pkt.Direction = DirectionInbound
	} else if d.localIPs[pkt.SrcIP.String()] {
		pkt.Direction = DirectionOutbound
	}

	// Apply direction filter.
	switch d.dirFilter {
	case "inbound":
		if pkt.Direction != DirectionInbound {
			return nil
		}
	case "outbound":
		if pkt.Direction != DirectionOutbound {
			return nil
		}
	}

	// Classify application protocol.
	if hasTransport {
		pkt.Protocol = ClassifyProtocol(pkt.Transport, pkt.SrcPort, pkt.DstPort)
	}

	return pkt
}

// ErrorCount returns the number of packets that failed to decode.
func (d *Decoder) ErrorCount() uint64 {
	return atomic.LoadUint64(&d.errorCount)
}
