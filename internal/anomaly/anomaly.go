package anomaly

import (
	"fmt"
	"sync"
	"time"

	"github.com/justinmaks/hoo/internal/config"
)

// AlertType identifies the kind of anomaly detected.
type AlertType string

const (
	AlertPortScan           AlertType = "PORT_SCAN"
	AlertDNSSpike           AlertType = "DNS_SPIKE"
	AlertConnectionFlood    AlertType = "CONN_FLOOD"
	AlertUnexpectedProtocol AlertType = "UNEXPECTED_PROTO"
)

// Alert is a timestamped anomaly detection event.
type Alert struct {
	Type      AlertType
	Timestamp time.Time
	Summary   string
	Details   string
}

const maxAlerts = 1000

// Detector runs anomaly detection rules against traffic state.
type Detector struct {
	cfg config.AnomalyConfig

	mu     sync.Mutex
	alerts []Alert

	// Port scan tracking: sourceIP -> set of destination ports with timestamps.
	portScans map[string]*portScanTracker

	// DNS rate tracking.
	dnsBaseline *rollingCounter
	dnsRecent   *rollingCounter

	// Connection flood tracking: sourceIP -> connection timestamps.
	connFloods map[string]*connectionTracker

	// Allowed ports set.
	allowedPorts map[int]bool
}

type portScanTracker struct {
	ports    map[uint16]time.Time
	alerted  bool
}

type connectionTracker struct {
	timestamps []time.Time
	alerted    bool
}

type rollingCounter struct {
	buckets  []uint64
	window   int
	idx      int
	lastTick time.Time
}

func newRollingCounter(windowSec int) *rollingCounter {
	return &rollingCounter{
		buckets: make([]uint64, windowSec),
		window:  windowSec,
	}
}

func (rc *rollingCounter) Add(now time.Time, count uint64) {
	sec := now.Truncate(time.Second)
	if sec != rc.lastTick {
		rc.idx = (rc.idx + 1) % rc.window
		rc.buckets[rc.idx] = 0
		rc.lastTick = sec
	}
	rc.buckets[rc.idx] += count
}

func (rc *rollingCounter) Sum() uint64 {
	var total uint64
	for _, b := range rc.buckets {
		total += b
	}
	return total
}

func (rc *rollingCounter) Average() float64 {
	return float64(rc.Sum()) / float64(rc.window)
}

// NewDetector creates an anomaly detector with the given config.
func NewDetector(cfg config.AnomalyConfig) *Detector {
	allowed := make(map[int]bool, len(cfg.AllowedPorts))
	for _, p := range cfg.AllowedPorts {
		allowed[p] = true
	}

	return &Detector{
		cfg:          cfg,
		portScans:    make(map[string]*portScanTracker),
		dnsBaseline:  newRollingCounter(300), // 5-minute baseline
		dnsRecent:    newRollingCounter(int(cfg.DNSSpikeWindow.Seconds())),
		connFloods:   make(map[string]*connectionTracker),
		allowedPorts: allowed,
	}
}

// CheckPortScan checks if a source IP is scanning ports.
func (d *Detector) CheckPortScan(srcIP string, dstPort uint16, isSYN bool, now time.Time) {
	if !isSYN {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	tracker, ok := d.portScans[srcIP]
	if !ok {
		tracker = &portScanTracker{ports: make(map[uint16]time.Time)}
		d.portScans[srcIP] = tracker
	}

	tracker.ports[dstPort] = now

	// Prune ports outside the window.
	cutoff := now.Add(-d.cfg.PortScanWindow)
	for port, ts := range tracker.ports {
		if ts.Before(cutoff) {
			delete(tracker.ports, port)
		}
	}

	if len(tracker.ports) >= d.cfg.PortScanPorts && !tracker.alerted {
		tracker.alerted = true
		d.addAlert(Alert{
			Type:      AlertPortScan,
			Timestamp: now,
			Summary:   fmt.Sprintf("Port scan from %s (%d ports)", srcIP, len(tracker.ports)),
			Details:   fmt.Sprintf("Source %s touched %d distinct ports in %s", srcIP, len(tracker.ports), d.cfg.PortScanWindow),
		})
	}
}

// CheckDNS tracks DNS packet rates and detects spikes.
func (d *Detector) CheckDNS(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.dnsBaseline.Add(now, 1)
	d.dnsRecent.Add(now, 1)

	baseline := d.dnsBaseline.Average()
	if baseline <= 0 {
		return
	}

	recentRate := float64(d.dnsRecent.Sum()) / float64(d.dnsRecent.window)
	factor := recentRate / baseline

	if factor >= d.cfg.DNSSpikeMultiplier {
		// Only alert once per spike window.
		if len(d.alerts) > 0 {
			last := d.alerts[len(d.alerts)-1]
			if last.Type == AlertDNSSpike && now.Sub(last.Timestamp) < d.cfg.DNSSpikeWindow {
				return
			}
		}
		d.addAlert(Alert{
			Type:      AlertDNSSpike,
			Timestamp: now,
			Summary:   fmt.Sprintf("DNS spike: %.1fx baseline", factor),
			Details:   fmt.Sprintf("DNS rate %.1fx above 5-min baseline over %s window", factor, d.cfg.DNSSpikeWindow),
		})
	}
}

// CheckConnectionFlood checks if a source IP is flooding connections.
func (d *Detector) CheckConnectionFlood(srcIP string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	tracker, ok := d.connFloods[srcIP]
	if !ok {
		tracker = &connectionTracker{}
		d.connFloods[srcIP] = tracker
	}

	tracker.timestamps = append(tracker.timestamps, now)

	// Prune timestamps outside the window.
	cutoff := now.Add(-d.cfg.ConnFloodWindow)
	start := 0
	for start < len(tracker.timestamps) && tracker.timestamps[start].Before(cutoff) {
		start++
	}
	tracker.timestamps = tracker.timestamps[start:]

	if len(tracker.timestamps) >= d.cfg.ConnFloodCount && !tracker.alerted {
		tracker.alerted = true
		d.addAlert(Alert{
			Type:      AlertConnectionFlood,
			Timestamp: now,
			Summary:   fmt.Sprintf("Connection flood from %s (%d conns)", srcIP, len(tracker.timestamps)),
			Details:   fmt.Sprintf("Source %s opened %d connections in %s", srcIP, len(tracker.timestamps), d.cfg.ConnFloodWindow),
		})
	}
}

// CheckUnexpectedProtocol flags traffic on ports not in the allowlist.
func (d *Detector) CheckUnexpectedProtocol(srcPort, dstPort uint16, bytesLen int, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.allowedPorts[int(srcPort)] || d.allowedPorts[int(dstPort)] {
		return
	}

	// Only alert once per unique port pair per session (check last alerts).
	port := dstPort
	if srcPort < dstPort {
		port = srcPort
	}

	for _, a := range d.alerts {
		if a.Type == AlertUnexpectedProtocol && a.Details == fmt.Sprintf("port:%d", port) {
			return
		}
	}

	d.addAlert(Alert{
		Type:      AlertUnexpectedProtocol,
		Timestamp: now,
		Summary:   fmt.Sprintf("Unexpected traffic on port %d", port),
		Details:   fmt.Sprintf("port:%d", port),
	})
}

func (d *Detector) addAlert(a Alert) {
	d.alerts = append(d.alerts, a)
	if len(d.alerts) > maxAlerts {
		// Keep the most recent half.
		copy(d.alerts, d.alerts[len(d.alerts)-maxAlerts/2:])
		d.alerts = d.alerts[:maxAlerts/2]
	}
}

// Alerts returns a copy of all alerts.
func (d *Detector) Alerts() []Alert {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Alert, len(d.alerts))
	copy(out, d.alerts)
	return out
}

// AlertCount returns the number of alerts.
func (d *Detector) AlertCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.alerts)
}

// Cleanup removes stale tracking data. Call periodically.
func (d *Detector) Cleanup(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Clean up port scan trackers that have no recent activity.
	cutoff := now.Add(-d.cfg.PortScanWindow * 2)
	for ip, tracker := range d.portScans {
		hasRecent := false
		for _, ts := range tracker.ports {
			if ts.After(cutoff) {
				hasRecent = true
				break
			}
		}
		if !hasRecent {
			delete(d.portScans, ip)
		}
	}

	// Clean up connection flood trackers.
	floodCutoff := now.Add(-d.cfg.ConnFloodWindow * 2)
	for ip, tracker := range d.connFloods {
		if len(tracker.timestamps) == 0 || tracker.timestamps[len(tracker.timestamps)-1].Before(floodCutoff) {
			delete(d.connFloods, ip)
		}
	}
}
