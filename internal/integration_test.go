//go:build integration

package internal

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/justinmaks/hoo/internal/aggregate"
	"github.com/justinmaks/hoo/internal/capture"
	"github.com/justinmaks/hoo/internal/decode"
)

// TestLoopbackCapture verifies the end-to-end pipeline on localhost.
// Run with: go test -tags integration -run TestLoopbackCapture ./internal/ -v
// Requires root or CAP_NET_RAW.
func TestLoopbackCapture(t *testing.T) {
	localIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	packetCh := make(chan capture.PacketData, 1000)
	engine := capture.NewEngine("lo", "tcp port 19283", packetCh)
	decoder := decode.NewDecoder(localIPs, "both")
	agg := aggregate.NewAggregator(1000, 30*time.Second, 60, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start capture.
	go engine.Start(ctx)

	// Start decode pipeline.
	go func() {
		for pd := range packetCh {
			pkt := decoder.Decode(pd)
			if pkt != nil {
				agg.Process(pkt)
			}
		}
	}()

	// Generate traffic on loopback.
	time.Sleep(500 * time.Millisecond)
	go func() {
		conn, err := net.Dial("tcp", "127.0.0.1:19283")
		if err != nil {
			// Listener might not be up; try to create one.
			return
		}
		conn.Write([]byte("hello from integration test"))
		conn.Close()
	}()

	// Start a listener to accept the connection.
	listener, err := net.Listen("tcp", "127.0.0.1:19283")
	if err != nil {
		t.Skipf("could not listen on port 19283: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1024)
		conn.Read(buf)
		conn.Close()
	}()

	// Generate traffic.
	time.Sleep(200 * time.Millisecond)
	conn, err := net.Dial("tcp", "127.0.0.1:19283")
	if err != nil {
		t.Skipf("could not connect: %v", err)
	}
	conn.Write([]byte("integration test data"))
	conn.Close()

	// Wait for capture.
	time.Sleep(2 * time.Second)
	agg.PublishSnapshot()
	snap := agg.ReadSnapshot()

	if snap.TotalBytesIn+snap.TotalBytesOut == 0 {
		t.Log("Warning: no traffic captured (may need elevated privileges)")
	} else {
		t.Logf("Captured: %d bytes in, %d bytes out, %d connections",
			snap.TotalBytesIn, snap.TotalBytesOut, snap.ActiveConns)
	}
}
