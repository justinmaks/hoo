package aggregate

import (
	"net"
	"testing"
	"time"

	"github.com/justinmaks/hoo/internal/decode"
)

func makeTestPacket(srcIP, dstIP string, srcPort, dstPort uint16, transport string, dir decode.Direction, length int) *decode.DecodedPacket {
	return &decode.DecodedPacket{
		SrcIP:     net.ParseIP(srcIP),
		DstIP:     net.ParseIP(dstIP),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Transport: transport,
		Protocol:  decode.ClassifyProtocol(transport, srcPort, dstPort),
		Direction: dir,
		Length:    length,
		Timestamp: time.Now().UnixNano(),
	}
}

func TestAggregatorProcess(t *testing.T) {
	agg := NewAggregator(1000, 30*time.Second, 60, 10)

	pkt := makeTestPacket("10.0.0.1", "192.168.1.100", 54321, 443, "TCP", decode.DirectionInbound, 1500)
	agg.Process(pkt)

	if agg.ConnectionCount() != 1 {
		t.Errorf("expected 1 connection, got %d", agg.ConnectionCount())
	}

	// Process another packet on same connection.
	agg.Process(pkt)
	if agg.ConnectionCount() != 1 {
		t.Errorf("expected still 1 connection, got %d", agg.ConnectionCount())
	}
}

func TestAggregatorSnapshot(t *testing.T) {
	agg := NewAggregator(1000, 30*time.Second, 60, 10)

	pkt := makeTestPacket("10.0.0.1", "192.168.1.100", 54321, 443, "TCP", decode.DirectionInbound, 1500)
	agg.Process(pkt)
	agg.PublishSnapshot()

	snap := agg.ReadSnapshot()
	if snap == nil {
		t.Fatal("snapshot is nil")
	}
	if len(snap.Connections) != 1 {
		t.Errorf("snapshot has %d connections, want 1", len(snap.Connections))
	}
	if snap.TotalBytesIn != 1500 {
		t.Errorf("TotalBytesIn = %d, want 1500", snap.TotalBytesIn)
	}
}

func TestAggregatorEviction(t *testing.T) {
	agg := NewAggregator(2, 1*time.Millisecond, 60, 10)

	// Fill to max.
	agg.Process(makeTestPacket("10.0.0.1", "192.168.1.100", 1, 443, "TCP", decode.DirectionInbound, 100))
	agg.Process(makeTestPacket("10.0.0.2", "192.168.1.100", 2, 443, "TCP", decode.DirectionInbound, 100))

	if agg.ConnectionCount() != 2 {
		t.Errorf("expected 2 connections, got %d", agg.ConnectionCount())
	}

	// Adding a third should evict one.
	agg.Process(makeTestPacket("10.0.0.3", "192.168.1.100", 3, 443, "TCP", decode.DirectionInbound, 100))
	if agg.ConnectionCount() != 2 {
		t.Errorf("expected 2 connections after eviction, got %d", agg.ConnectionCount())
	}
}

func TestTCPStateMachine(t *testing.T) {
	tests := []struct {
		current  TCPState
		flags    decode.TCPFlags
		expected TCPState
	}{
		{TCPStateNew, decode.TCPFlags{SYN: true}, TCPStateSYNSent},
		{TCPStateSYNSent, decode.TCPFlags{SYN: true, ACK: true}, TCPStateSYNReceived},
		{TCPStateSYNReceived, decode.TCPFlags{ACK: true}, TCPStateEstablished},
		{TCPStateEstablished, decode.TCPFlags{FIN: true}, TCPStateFinWait},
		{TCPStateEstablished, decode.TCPFlags{RST: true}, TCPStateReset},
		{TCPStateFinWait, decode.TCPFlags{FIN: true}, TCPStateTimeWait},
		{TCPStateTimeWait, decode.TCPFlags{ACK: true}, TCPStateClosed},
	}

	for _, tt := range tests {
		got := UpdateTCPState(tt.current, tt.flags, true)
		if got != tt.expected {
			t.Errorf("UpdateTCPState(%s, %+v) = %s, want %s", tt.current, tt.flags, got, tt.expected)
		}
	}
}

func TestProtocolDistribution(t *testing.T) {
	agg := NewAggregator(1000, 30*time.Second, 60, 10)

	agg.Process(makeTestPacket("10.0.0.1", "192.168.1.100", 54321, 443, "TCP", decode.DirectionInbound, 1000))
	agg.Process(makeTestPacket("10.0.0.1", "192.168.1.100", 54321, 80, "TCP", decode.DirectionInbound, 500))
	agg.PublishSnapshot()

	snap := agg.ReadSnapshot()
	if len(snap.Protocols) < 2 {
		t.Errorf("expected at least 2 protocols, got %d", len(snap.Protocols))
	}
}
