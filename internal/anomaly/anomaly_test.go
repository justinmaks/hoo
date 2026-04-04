package anomaly

import (
	"testing"
	"time"

	"github.com/justinmaks/hoo/internal/config"
)

func defaultCfg() config.AnomalyConfig {
	return config.AnomalyConfig{
		PortScanPorts:      10,
		PortScanWindow:     60 * time.Second,
		DNSSpikeMultiplier: 10,
		DNSSpikeWindow:     30 * time.Second,
		ConnFloodCount:     50,
		ConnFloodWindow:    10 * time.Second,
		AllowedPorts:       []int{80, 443, 53, 22},
	}
}

func TestPortScanDetection(t *testing.T) {
	d := NewDetector(defaultCfg())
	now := time.Now()

	// Below threshold.
	for i := uint16(0); i < 5; i++ {
		d.CheckPortScan("10.0.0.1", 1000+i, true, now)
	}
	if d.AlertCount() != 0 {
		t.Error("should not alert below threshold")
	}

	// At threshold.
	for i := uint16(5); i < 12; i++ {
		d.CheckPortScan("10.0.0.1", 1000+i, true, now)
	}
	if d.AlertCount() != 1 {
		t.Errorf("expected 1 alert, got %d", d.AlertCount())
	}
}

func TestConnectionFloodDetection(t *testing.T) {
	d := NewDetector(defaultCfg())
	now := time.Now()

	for i := 0; i < 50; i++ {
		d.CheckConnectionFlood("10.0.0.1", now.Add(time.Duration(i)*time.Millisecond))
	}
	if d.AlertCount() != 1 {
		t.Errorf("expected 1 flood alert, got %d", d.AlertCount())
	}
}

func TestUnexpectedProtocol(t *testing.T) {
	d := NewDetector(defaultCfg())
	now := time.Now()

	// Allowed port — no alert.
	d.CheckUnexpectedProtocol(54321, 443, 100, now)
	if d.AlertCount() != 0 {
		t.Error("should not alert on allowed port")
	}

	// Unexpected port.
	d.CheckUnexpectedProtocol(54321, 4444, 100, now)
	if d.AlertCount() != 1 {
		t.Errorf("expected 1 alert, got %d", d.AlertCount())
	}
}

func TestCleanup(t *testing.T) {
	d := NewDetector(defaultCfg())
	now := time.Now()

	d.CheckPortScan("10.0.0.1", 1000, true, now.Add(-5*time.Minute))
	d.Cleanup(now)

	// Tracker should be cleaned up.
	d.mu.Lock()
	count := len(d.portScans)
	d.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 port scan trackers after cleanup, got %d", count)
	}
}
