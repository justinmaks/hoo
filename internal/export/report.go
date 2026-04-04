package export

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/justinmaks/hoo/internal/aggregate"
	"github.com/justinmaks/hoo/internal/anomaly"
	"github.com/justinmaks/hoo/internal/resolve"
)

// ReportData holds all data for a session report.
type ReportData struct {
	Interface    string              `json:"interface"`
	StartTime    time.Time           `json:"start_time"`
	EndTime      time.Time           `json:"end_time"`
	Duration     string              `json:"duration"`
	TotalBytesIn  uint64             `json:"total_bytes_in"`
	TotalBytesOut uint64             `json:"total_bytes_out"`
	ActiveConns  int                 `json:"active_connections"`
	Protocols    []aggregate.ProtocolStat `json:"protocols"`
	TopTalkers   []talkerEntry       `json:"top_talkers"`
	Anomalies    []anomalyEntry      `json:"anomalies"`
}

type talkerEntry struct {
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	TotalBytes  uint64 `json:"total_bytes"`
	Connections int    `json:"connections"`
}

type anomalyEntry struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Summary   string `json:"summary"`
	Details   string `json:"details"`
}

// ReportGenerator creates session reports.
type ReportGenerator struct {
	resolver  *resolve.Resolver
	iface     string
	startTime time.Time
}

// NewReportGenerator creates a report generator.
func NewReportGenerator(resolver *resolve.Resolver, iface string, startTime time.Time) *ReportGenerator {
	return &ReportGenerator{
		resolver:  resolver,
		iface:     iface,
		startTime: startTime,
	}
}

// BuildReportData assembles report data from current state.
func (g *ReportGenerator) BuildReportData(snap *aggregate.Snapshot, alerts []anomaly.Alert) ReportData {
	now := time.Now()
	data := ReportData{
		Interface:     g.iface,
		StartTime:     g.startTime,
		EndTime:       now,
		Duration:      now.Sub(g.startTime).Truncate(time.Second).String(),
		TotalBytesIn:  snap.TotalBytesIn,
		TotalBytesOut: snap.TotalBytesOut,
		ActiveConns:   snap.ActiveConns,
		Protocols:     snap.Protocols,
	}

	for _, t := range snap.TopTalkers {
		hostname := t.IP.String()
		if g.resolver != nil {
			hostname = g.resolver.Lookup(hostname)
		}
		data.TopTalkers = append(data.TopTalkers, talkerEntry{
			IP:          t.IP.String(),
			Hostname:    hostname,
			TotalBytes:  t.TotalBytes,
			Connections: t.Connections,
		})
	}

	for _, a := range alerts {
		data.Anomalies = append(data.Anomalies, anomalyEntry{
			Timestamp: a.Timestamp.Format(time.RFC3339),
			Type:      string(a.Type),
			Summary:   a.Summary,
			Details:   a.Details,
		})
	}

	return data
}

// WriteMarkdown writes a Markdown report.
func (g *ReportGenerator) WriteMarkdown(path string, data ReportData) error {
	var sb strings.Builder

	sb.WriteString("# hoo Network Traffic Report\n\n")
	sb.WriteString("## Session Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Interface:** %s\n", data.Interface))
	sb.WriteString(fmt.Sprintf("- **Start:** %s\n", data.StartTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **End:** %s\n", data.EndTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Duration:** %s\n", data.Duration))
	sb.WriteString(fmt.Sprintf("- **Bytes received:** %d\n", data.TotalBytesIn))
	sb.WriteString(fmt.Sprintf("- **Bytes sent:** %d\n", data.TotalBytesOut))
	sb.WriteString(fmt.Sprintf("- **Active connections:** %d\n", data.ActiveConns))

	sb.WriteString("\n## Protocol Distribution\n\n")
	sb.WriteString("| Protocol | Bytes | Packets | Percentage |\n")
	sb.WriteString("|----------|-------|---------|------------|\n")
	for _, p := range data.Protocols {
		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %.1f%% |\n",
			string(p.Protocol), p.Bytes, p.Packets, p.Percentage))
	}

	sb.WriteString("\n## Top Remote Hosts\n\n")
	sb.WriteString("| Rank | IP | Hostname | Total Bytes | Connections |\n")
	sb.WriteString("|------|----|---------:|-------------|-------------|\n")
	for i, t := range data.TopTalkers {
		sb.WriteString(fmt.Sprintf("| %d | %s | %s | %d | %d |\n",
			i+1, t.IP, t.Hostname, t.TotalBytes, t.Connections))
	}

	if len(data.Anomalies) > 0 {
		sb.WriteString("\n## Anomalies\n\n")
		sb.WriteString("| Time | Type | Summary |\n")
		sb.WriteString("|------|------|---------|\n")
		for _, a := range data.Anomalies {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", a.Timestamp, a.Type, a.Summary))
		}
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// WriteJSON writes a JSON report.
func (g *ReportGenerator) WriteJSON(path string, data ReportData) error {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0644)
}

// WriteReport writes a report in the specified format.
func (g *ReportGenerator) WriteReport(path, format string, data ReportData) error {
	switch format {
	case "json":
		return g.WriteJSON(path, data)
	case "markdown", "md":
		return g.WriteMarkdown(path, data)
	default:
		return fmt.Errorf("unknown report format: %s", format)
	}
}
