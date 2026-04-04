package aggregate

import (
	"fmt"
	"net"
	"time"

	"github.com/justinmaks/hoo/internal/decode"
)

// TCPState represents the state of a TCP connection.
type TCPState int

const (
	TCPStateNew TCPState = iota
	TCPStateSYNSent
	TCPStateSYNReceived
	TCPStateEstablished
	TCPStateFinWait
	TCPStateCloseWait
	TCPStateClosed
	TCPStateReset
	TCPStateTimeWait
)

func (s TCPState) String() string {
	switch s {
	case TCPStateNew:
		return "NEW"
	case TCPStateSYNSent:
		return "SYN_SENT"
	case TCPStateSYNReceived:
		return "SYN_RCVD"
	case TCPStateEstablished:
		return "ESTABLISHED"
	case TCPStateFinWait:
		return "FIN_WAIT"
	case TCPStateCloseWait:
		return "CLOSE_WAIT"
	case TCPStateClosed:
		return "CLOSED"
	case TCPStateReset:
		return "RESET"
	case TCPStateTimeWait:
		return "TIME_WAIT"
	default:
		return "UNKNOWN"
	}
}

// IsTerminal returns true if the connection is in a terminal state.
func (s TCPState) IsTerminal() bool {
	return s == TCPStateClosed || s == TCPStateReset || s == TCPStateTimeWait
}

// ConnKey is a 5-tuple connection identifier.
type ConnKey struct {
	Proto   string
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

func (k ConnKey) String() string {
	return fmt.Sprintf("%s %s:%d -> %s:%d", k.Proto, k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}

// Connection holds state for a tracked connection.
type Connection struct {
	Key          ConnKey
	BytesIn      uint64
	BytesOut     uint64
	PacketsIn    uint64
	PacketsOut   uint64
	StartTime    time.Time
	LastActivity time.Time
	TCPState     TCPState
	Protocol     decode.Protocol
	Direction    decode.Direction
	LocalIP      net.IP
	RemoteIP     net.IP
	RemotePort   uint16
	LocalPort    uint16
}

// MakeConnKey creates a normalized connection key from a decoded packet.
// The key is always ordered so that the lower IP:port is src.
func MakeConnKey(pkt *decode.DecodedPacket) ConnKey {
	srcIP := pkt.SrcIP.String()
	dstIP := pkt.DstIP.String()

	// Normalize: always put the "smaller" side as src for consistency.
	if srcIP > dstIP || (srcIP == dstIP && pkt.SrcPort > pkt.DstPort) {
		return ConnKey{
			Proto:   pkt.Transport,
			SrcIP:   dstIP,
			SrcPort: pkt.DstPort,
			DstIP:   srcIP,
			DstPort: pkt.SrcPort,
		}
	}
	return ConnKey{
		Proto:   pkt.Transport,
		SrcIP:   srcIP,
		SrcPort: pkt.SrcPort,
		DstIP:   dstIP,
		DstPort: pkt.DstPort,
	}
}

// UpdateTCPState advances the TCP state machine based on packet flags.
func UpdateTCPState(current TCPState, flags decode.TCPFlags, isFromSrc bool) TCPState {
	if flags.RST {
		return TCPStateReset
	}

	switch current {
	case TCPStateNew:
		if flags.SYN && !flags.ACK {
			return TCPStateSYNSent
		}
		// Data without handshake (mid-stream capture).
		return TCPStateEstablished

	case TCPStateSYNSent:
		if flags.SYN && flags.ACK {
			return TCPStateSYNReceived
		}
		return current

	case TCPStateSYNReceived:
		if flags.ACK && !flags.SYN {
			return TCPStateEstablished
		}
		return current

	case TCPStateEstablished:
		if flags.FIN {
			return TCPStateFinWait
		}
		return current

	case TCPStateFinWait:
		if flags.FIN {
			return TCPStateTimeWait
		}
		if flags.ACK {
			return TCPStateCloseWait
		}
		return current

	case TCPStateCloseWait:
		if flags.FIN {
			return TCPStateTimeWait
		}
		return current

	case TCPStateTimeWait:
		if flags.ACK {
			return TCPStateClosed
		}
		return current
	}

	return current
}
