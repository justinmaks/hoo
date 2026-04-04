package aggregate

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/justinmaks/hoo/internal/decode"
)

const (
	DefaultMaxConnections = 50000
	DefaultHoldTime       = 30 * time.Second
	DefaultStatsWindow    = 60
	DefaultTopN           = 10
)

// BandwidthBucket holds per-second bandwidth counters.
type BandwidthBucket struct {
	Timestamp  time.Time
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
}

// TopTalker represents a remote IP ranked by bandwidth.
type TopTalker struct {
	IP          net.IP
	Hostname    string
	TotalBytes  uint64
	Connections int
}

// ProtocolStat holds per-protocol traffic counters.
type ProtocolStat struct {
	Protocol   decode.Protocol
	Bytes      uint64
	Packets    uint64
	Percentage float64
}

// Snapshot is an immutable point-in-time view of all aggregated state.
type Snapshot struct {
	Connections    []Connection
	Bandwidth      []BandwidthBucket
	CurrentBPS     BandwidthBucket
	TopTalkers     []TopTalker
	Protocols      []ProtocolStat
	TotalBytesIn   uint64
	TotalBytesOut  uint64
	TotalPacketsIn uint64
	TotalPacketsOut uint64
	ActiveConns    int
	Timestamp      time.Time
}

// Aggregator processes decoded packets and maintains all traffic state.
type Aggregator struct {
	maxConns   int
	holdTime   time.Duration
	statsWindow int
	topN       int

	// Connection table.
	mu    sync.Mutex
	conns map[ConnKey]*Connection

	// Bandwidth buckets (ring buffer).
	buckets    []BandwidthBucket
	bucketIdx  int
	lastBucket time.Time

	// Protocol counters.
	protoBytes   map[decode.Protocol]uint64
	protoPackets map[decode.Protocol]uint64

	// Session totals.
	totalBytesIn   uint64
	totalBytesOut  uint64
	totalPacketsIn uint64
	totalPacketsOut uint64

	// Double-buffered snapshot for lock-free TUI reads.
	snapshotA atomic.Pointer[Snapshot]
}

// NewAggregator creates an Aggregator with the given settings.
func NewAggregator(maxConns int, holdTime time.Duration, statsWindow, topN int) *Aggregator {
	if maxConns <= 0 {
		maxConns = DefaultMaxConnections
	}
	if holdTime <= 0 {
		holdTime = DefaultHoldTime
	}
	if statsWindow <= 0 {
		statsWindow = DefaultStatsWindow
	}
	if topN <= 0 {
		topN = DefaultTopN
	}

	a := &Aggregator{
		maxConns:     maxConns,
		holdTime:     holdTime,
		statsWindow:  statsWindow,
		topN:         topN,
		conns:        make(map[ConnKey]*Connection),
		buckets:      make([]BandwidthBucket, statsWindow),
		protoBytes:   make(map[decode.Protocol]uint64),
		protoPackets: make(map[decode.Protocol]uint64),
	}

	// Initialize with empty snapshot.
	empty := &Snapshot{Timestamp: time.Now()}
	a.snapshotA.Store(empty)

	return a
}

// Process ingests a decoded packet and updates all tracked state.
func (a *Aggregator) Process(pkt *decode.DecodedPacket) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Unix(0, pkt.Timestamp)
	key := MakeConnKey(pkt)

	// Update bandwidth bucket.
	a.updateBucket(now, pkt)

	// Update protocol counters.
	a.protoBytes[pkt.Protocol] += uint64(pkt.Length)
	a.protoPackets[pkt.Protocol]++

	// Update session totals.
	if pkt.Direction == decode.DirectionInbound {
		a.totalBytesIn += uint64(pkt.Length)
		a.totalPacketsIn++
	} else {
		a.totalBytesOut += uint64(pkt.Length)
		a.totalPacketsOut++
	}

	// Update or create connection.
	conn, exists := a.conns[key]
	if !exists {
		conn = a.createConnection(key, pkt, now)
	}

	conn.LastActivity = now

	if pkt.Direction == decode.DirectionInbound {
		conn.BytesIn += uint64(pkt.Length)
		conn.PacketsIn++
	} else {
		conn.BytesOut += uint64(pkt.Length)
		conn.PacketsOut++
	}

	// Update TCP state if applicable.
	if pkt.Transport == "TCP" {
		isFromSrc := pkt.SrcIP.String() == key.SrcIP
		conn.TCPState = UpdateTCPState(conn.TCPState, pkt.TCPFlags, isFromSrc)
	}
}

func (a *Aggregator) createConnection(key ConnKey, pkt *decode.DecodedPacket, now time.Time) *Connection {
	// Enforce max connections — evict oldest idle.
	if len(a.conns) >= a.maxConns {
		a.evictOldest()
	}

	conn := &Connection{
		Key:       key,
		StartTime: now,
		Protocol:  pkt.Protocol,
		Direction: pkt.Direction,
	}

	// Determine remote vs local.
	if pkt.Direction == decode.DirectionInbound {
		conn.LocalIP = pkt.DstIP
		conn.RemoteIP = pkt.SrcIP
		conn.RemotePort = pkt.SrcPort
		conn.LocalPort = pkt.DstPort
	} else {
		conn.LocalIP = pkt.SrcIP
		conn.RemoteIP = pkt.DstIP
		conn.RemotePort = pkt.DstPort
		conn.LocalPort = pkt.SrcPort
	}

	if pkt.Transport == "TCP" {
		if pkt.TCPFlags.SYN && !pkt.TCPFlags.ACK {
			conn.TCPState = TCPStateSYNSent
		} else {
			conn.TCPState = TCPStateEstablished
		}
	}

	a.conns[key] = conn
	return conn
}

func (a *Aggregator) updateBucket(now time.Time, pkt *decode.DecodedPacket) {
	sec := now.Truncate(time.Second)
	if sec != a.lastBucket {
		a.bucketIdx = (a.bucketIdx + 1) % a.statsWindow
		a.buckets[a.bucketIdx] = BandwidthBucket{Timestamp: sec}
		a.lastBucket = sec
	}

	b := &a.buckets[a.bucketIdx]
	if pkt.Direction == decode.DirectionInbound {
		b.BytesIn += uint64(pkt.Length)
		b.PacketsIn++
	} else {
		b.BytesOut += uint64(pkt.Length)
		b.PacketsOut++
	}
}

// EvictExpired removes connections that have been in a terminal state
// longer than the hold time. Call this periodically (e.g. every second).
func (a *Aggregator) EvictExpired() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for key, conn := range a.conns {
		if conn.TCPState.IsTerminal() && now.Sub(conn.LastActivity) > a.holdTime {
			delete(a.conns, key)
		}
	}
}

func (a *Aggregator) evictOldest() {
	var oldestKey ConnKey
	var oldestTime time.Time
	first := true

	for key, conn := range a.conns {
		if first || conn.LastActivity.Before(oldestTime) {
			oldestKey = key
			oldestTime = conn.LastActivity
			first = false
		}
	}

	if !first {
		delete(a.conns, oldestKey)
	}
}

// PublishSnapshot builds and atomically publishes a new snapshot.
// Call this on the aggregation tick (e.g. 1 Hz).
func (a *Aggregator) PublishSnapshot() {
	a.mu.Lock()
	snap := a.buildSnapshotLocked()
	a.mu.Unlock()

	a.snapshotA.Store(snap)
}

// ReadSnapshot returns the latest published snapshot. Lock-free.
func (a *Aggregator) ReadSnapshot() *Snapshot {
	return a.snapshotA.Load()
}

func (a *Aggregator) buildSnapshotLocked() *Snapshot {
	snap := &Snapshot{
		Timestamp:       time.Now(),
		ActiveConns:     len(a.conns),
		TotalBytesIn:    a.totalBytesIn,
		TotalBytesOut:   a.totalBytesOut,
		TotalPacketsIn:  a.totalPacketsIn,
		TotalPacketsOut: a.totalPacketsOut,
	}

	// Copy connections.
	snap.Connections = make([]Connection, 0, len(a.conns))
	for _, c := range a.conns {
		snap.Connections = append(snap.Connections, *c)
	}

	// Copy bandwidth buckets in time order.
	snap.Bandwidth = make([]BandwidthBucket, 0, a.statsWindow)
	for i := 1; i <= a.statsWindow; i++ {
		idx := (a.bucketIdx + i) % a.statsWindow
		b := a.buckets[idx]
		if !b.Timestamp.IsZero() {
			snap.Bandwidth = append(snap.Bandwidth, b)
		}
	}

	// Current BPS is the latest bucket.
	if len(snap.Bandwidth) > 0 {
		snap.CurrentBPS = snap.Bandwidth[len(snap.Bandwidth)-1]
	}

	// Compute top talkers.
	snap.TopTalkers = a.computeTopTalkers()

	// Compute protocol distribution.
	snap.Protocols = a.computeProtocolDist()

	return snap
}

func (a *Aggregator) computeTopTalkers() []TopTalker {
	// Aggregate by remote IP.
	type ipStats struct {
		totalBytes  uint64
		connections int
		ip          net.IP
	}

	byIP := make(map[string]*ipStats)
	for _, conn := range a.conns {
		ipStr := conn.RemoteIP.String()
		s, ok := byIP[ipStr]
		if !ok {
			s = &ipStats{ip: conn.RemoteIP}
			byIP[ipStr] = s
		}
		s.totalBytes += conn.BytesIn + conn.BytesOut
		s.connections++
	}

	// Sort by total bytes descending.
	talkers := make([]TopTalker, 0, len(byIP))
	for _, s := range byIP {
		talkers = append(talkers, TopTalker{
			IP:          s.ip,
			TotalBytes:  s.totalBytes,
			Connections: s.connections,
		})
	}
	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].TotalBytes > talkers[j].TotalBytes
	})

	if len(talkers) > a.topN {
		talkers = talkers[:a.topN]
	}

	return talkers
}

func (a *Aggregator) computeProtocolDist() []ProtocolStat {
	var totalBytes uint64
	for _, b := range a.protoBytes {
		totalBytes += b
	}

	stats := make([]ProtocolStat, 0, len(a.protoBytes))
	for _, proto := range decode.AllProtocols() {
		b := a.protoBytes[proto]
		p := a.protoPackets[proto]
		if b == 0 && p == 0 {
			continue
		}
		var pct float64
		if totalBytes > 0 {
			pct = float64(b) / float64(totalBytes) * 100
		}
		stats = append(stats, ProtocolStat{
			Protocol:   proto,
			Bytes:      b,
			Packets:    p,
			Percentage: pct,
		})
	}

	return stats
}

// ConnectionCount returns the number of active connections (for quick checks).
func (a *Aggregator) ConnectionCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.conns)
}

// GetConnections returns a copy of all current connections (for use by anomaly detection).
func (a *Aggregator) GetConnections() []Connection {
	a.mu.Lock()
	defer a.mu.Unlock()
	conns := make([]Connection, 0, len(a.conns))
	for _, c := range a.conns {
		conns = append(conns, *c)
	}
	return conns
}
