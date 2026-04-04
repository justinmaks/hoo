package export

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinmaks/hoo/internal/aggregate"
	"github.com/justinmaks/hoo/internal/decode"
)

func testSnapshot() *aggregate.Snapshot {
	return &aggregate.Snapshot{
		Connections: []aggregate.Connection{
			{
				Key: aggregate.ConnKey{
					Proto:   "TCP",
					SrcIP:   "10.0.0.1",
					SrcPort: 54321,
					DstIP:   "192.168.1.100",
					DstPort: 443,
				},
				BytesIn:      1500,
				BytesOut:     500,
				PacketsIn:    10,
				PacketsOut:   5,
				StartTime:    time.Now().Add(-5 * time.Minute),
				LastActivity: time.Now(),
				TCPState:     aggregate.TCPStateEstablished,
				Protocol:     decode.ProtoHTTPS,
				Direction:    decode.DirectionInbound,
				RemoteIP:     net.ParseIP("10.0.0.1"),
				RemotePort:   54321,
				LocalPort:    443,
			},
		},
		Bandwidth: []aggregate.BandwidthBucket{
			{Timestamp: time.Now(), BytesIn: 1500, BytesOut: 500, PacketsIn: 10, PacketsOut: 5},
		},
		TotalBytesIn:  1500,
		TotalBytesOut: 500,
		ActiveConns:   1,
		Timestamp:     time.Now(),
	}
}

func TestCSVWriterConnections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.csv")

	w := NewCSVWriter(nil)
	snap := testSnapshot()

	err := w.WriteConnections(path, snap, false)
	if err != nil {
		t.Fatalf("WriteConnections: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "# hoo export v1 connections") {
		t.Error("missing schema version comment")
	}
	if !strings.Contains(content, "timestamp,protocol") {
		t.Error("missing header row")
	}
}

func TestCSVWriterAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.csv")

	w := NewCSVWriter(nil)
	snap := testSnapshot()

	// First write.
	w.WriteConnections(path, snap, false)

	// Append.
	w.WriteConnections(path, snap, true)

	data, _ := os.ReadFile(path)
	content := string(data)

	// Should have schema comment only once.
	if strings.Count(content, "# hoo export") != 1 {
		t.Error("schema comment duplicated in append mode")
	}
}

func TestCheckFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.csv")
	os.WriteFile(path, []byte("test"), 0644)

	err := CheckFileExists(path, false)
	if err == nil {
		t.Error("expected error for existing file without overwrite")
	}

	err = CheckFileExists(path, true)
	if err != nil {
		t.Error("should not error with overwrite=true")
	}

	err = CheckFileExists(filepath.Join(dir, "nonexistent.csv"), false)
	if err != nil {
		t.Error("should not error for nonexistent file")
	}
}

func TestTimestampedFilename(t *testing.T) {
	name := TimestampedFilename("hoo_export", "csv")
	if !strings.HasPrefix(name, "hoo_export_") {
		t.Errorf("unexpected prefix: %s", name)
	}
	if !strings.HasSuffix(name, ".csv") {
		t.Errorf("unexpected suffix: %s", name)
	}
}
