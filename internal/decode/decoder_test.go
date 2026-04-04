package decode

import (
	"net"
	"testing"
)

func TestClassifyProtocol(t *testing.T) {
	tests := []struct {
		transport string
		srcPort   uint16
		dstPort   uint16
		want      Protocol
	}{
		{"TCP", 54321, 443, ProtoHTTPS},
		{"TCP", 443, 54321, ProtoHTTPS},
		{"TCP", 54321, 80, ProtoHTTP},
		{"UDP", 54321, 53, ProtoDNS},
		{"TCP", 54321, 53, ProtoDNS},
		{"TCP", 54321, 22, ProtoSSH},
		{"TCP", 54321, 9200, ProtoOther},
		{"UDP", 12345, 6789, ProtoOther},
	}

	for _, tt := range tests {
		got := ClassifyProtocol(tt.transport, tt.srcPort, tt.dstPort)
		if got != tt.want {
			t.Errorf("ClassifyProtocol(%s, %d, %d) = %s, want %s",
				tt.transport, tt.srcPort, tt.dstPort, got, tt.want)
		}
	}
}

func TestAllProtocols(t *testing.T) {
	protos := AllProtocols()
	if len(protos) != 5 {
		t.Errorf("AllProtocols() returned %d protocols, want 5", len(protos))
	}
}

func TestNewDecoder(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.168.1.100")}
	d := NewDecoder(ips, "both")
	if d == nil {
		t.Fatal("NewDecoder returned nil")
	}
	if !d.localIPs["192.168.1.100"] {
		t.Error("local IP not registered")
	}
	if d.ErrorCount() != 0 {
		t.Error("initial error count should be 0")
	}
}
