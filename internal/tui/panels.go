package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/justinmaks/hoo/internal/aggregate"
	"github.com/justinmaks/hoo/internal/resolve"
)

// SortColumn defines what column to sort the connection table by.
type SortColumn int

const (
	SortByRate SortColumn = iota
	SortByProtocol
	SortByRemote
	SortByState
	sortColumnCount
)

func (s SortColumn) String() string {
	switch s {
	case SortByRate:
		return "Rate"
	case SortByProtocol:
		return "Proto"
	case SortByRemote:
		return "Remote"
	case SortByState:
		return "State"
	default:
		return "?"
	}
}

func renderConnectionTable(conns []aggregate.Connection, width, height int, cursor int, sortCol SortColumn, sortDesc bool, search string, resolver *resolve.Resolver) string {
	// Filter by search.
	var filtered []aggregate.Connection
	if search != "" {
		for _, c := range conns {
			s := c.Key.String()
			if resolver != nil {
				s += " " + resolver.Lookup(c.RemoteIP.String())
			}
			if strings.Contains(strings.ToLower(s), strings.ToLower(search)) {
				filtered = append(filtered, c)
			}
		}
	} else {
		filtered = conns
	}

	// Sort.
	sort.Slice(filtered, func(i, j int) bool {
		var less bool
		switch sortCol {
		case SortByRate:
			ri := filtered[i].BytesIn + filtered[i].BytesOut
			rj := filtered[j].BytesIn + filtered[j].BytesOut
			less = ri > rj // descending by default
		case SortByProtocol:
			less = string(filtered[i].Protocol) < string(filtered[j].Protocol)
		case SortByRemote:
			ri, rj := "", ""
			if filtered[i].RemoteIP != nil {
				ri = filtered[i].RemoteIP.String()
			}
			if filtered[j].RemoteIP != nil {
				rj = filtered[j].RemoteIP.String()
			}
			less = ri < rj
		case SortByState:
			less = filtered[i].TCPState < filtered[j].TCPState
		}
		if sortDesc {
			less = !less
		}
		return less
	})

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Connections"))
	sb.WriteString(fmt.Sprintf("  (%d active, sort: %s)", len(filtered), sortCol))
	if search != "" {
		sb.WriteString(fmt.Sprintf("  filter: %s", search))
	}
	sb.WriteByte('\n')

	// Dynamic column widths based on available space.
	// Columns: Proto(5) + Local(addrW) + Remote(addrW) + Bytes(10) + State(11) + gaps(8)
	addrW := (width - 5 - 10 - 11 - 8) / 2
	if addrW < 18 {
		addrW = 18
	}
	if addrW > 40 {
		addrW = 40
	}

	fmtStr := fmt.Sprintf("%%-%ds %%-%ds %%-%ds %%10s %%-%ds", 5, addrW, addrW, 11)

	header := fmt.Sprintf(fmtStr, "Proto", "Local", "Remote", "Bytes", "State")
	sb.WriteString(headerStyle.Render(header))
	sb.WriteByte('\n')

	// Visible rows.
	maxRows := height - 3
	if maxRows < 1 {
		maxRows = 1
	}

	startIdx := 0
	if cursor >= maxRows {
		startIdx = cursor - maxRows + 1
	}

	for i := startIdx; i < len(filtered) && i < startIdx+maxRows; i++ {
		c := filtered[i]

		// Build local address.
		localAddr := fmt.Sprintf("%s:%d", c.LocalIP, c.LocalPort)
		if c.LocalIP == nil {
			localAddr = fmt.Sprintf(":%d", c.LocalPort)
		}

		// Build remote address with hostname if available.
		remoteIP := "<unknown>"
		if c.RemoteIP != nil {
			remoteIP = c.RemoteIP.String()
		}
		remoteDisplay := remoteIP
		if resolver != nil {
			if hostname := resolver.Lookup(remoteIP); hostname != remoteIP {
				remoteDisplay = hostname
			}
		}
		remoteAddr := fmt.Sprintf("%s:%d", truncate(remoteDisplay, addrW-7), c.RemotePort)

		totalBytes := c.BytesIn + c.BytesOut
		state := ""
		if c.Key.Proto == "TCP" {
			state = c.TCPState.String()
		}

		row := fmt.Sprintf(fmtStr,
			c.Key.Proto, truncate(localAddr, addrW), truncate(remoteAddr, addrW), formatBytes(totalBytes), state)

		if i == cursor {
			sb.WriteString(selectedRowStyle.Render(row))
		} else {
			sb.WriteString(row)
		}
		sb.WriteByte('\n')
	}

	return sb.String()
}

func renderProtocolBreakdown(stats []aggregate.ProtocolStat, width int) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Protocol Distribution"))
	sb.WriteByte('\n')

	barWidth := width - 30
	if barWidth < 10 {
		barWidth = 10
	}

	for _, s := range stats {
		barLen := int(s.Percentage * float64(barWidth) / 100)
		if barLen < 0 {
			barLen = 0
		}
		bar := strings.Repeat("█", barLen) + strings.Repeat("░", barWidth-barLen)
		sb.WriteString(fmt.Sprintf("%-6s %s %5.1f%% %s\n",
			string(s.Protocol), bar, s.Percentage, formatBytes(s.Bytes)))
	}

	return sb.String()
}

func renderTopTalkers(talkers []aggregate.TopTalker, resolver *resolve.Resolver) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Top Talkers"))
	sb.WriteByte('\n')

	for i, t := range talkers {
		hostname := t.IP.String()
		if resolver != nil {
			if resolved := resolver.Lookup(hostname); resolved != hostname {
				hostname = resolved
			}
		}

		sb.WriteString(fmt.Sprintf("%2d. %-30s %10s  %d conns\n",
			i+1, truncate(hostname, 30), formatBytes(t.TotalBytes), t.Connections))
	}

	if len(talkers) == 0 {
		sb.WriteString(dimStyle.Render("  No traffic yet\n"))
	}

	return sb.String()
}

func renderStatusBar(width int, filter string, paused bool, dropCount uint64, alertCount int, lastAlert string) string {
	var parts []string

	if filter != "" {
		parts = append(parts, fmt.Sprintf("filter: %s", filter))
	}

	if paused {
		parts = append(parts, pausedStyle.Render("PAUSED"))
	} else {
		parts = append(parts, "CAPTURING")
	}

	if dropCount > 0 {
		parts = append(parts, fmt.Sprintf("drops: %d", dropCount))
	}

	if alertCount > 0 {
		parts = append(parts, alertStyle.Render(fmt.Sprintf("⚠ %d alerts", alertCount)))
		if lastAlert != "" {
			parts = append(parts, lastAlert)
		}
	}

	right := "q:quit  ?:help  p:pause  /:filter  1-7:views  e:export  r:report"

	left := strings.Join(parts, "  │  ")
	padding := width - len(left) - len(right)
	if padding < 1 {
		padding = 1
	}

	return statusBarStyle.Width(width).Render(left + strings.Repeat(" ", padding) + right)
}

func renderHelp(width, height int) string {
	help := `KEYBOARD SHORTCUTS

Navigation
  ↑/↓/j/k    Scroll table
  1           Bandwidth view
  2           Connections view
  3           Protocol breakdown
  4           Network map
  5           Open ports
  6           Inbound traffic
  7           Outbound traffic

Controls
  p           Pause/resume capture
  s           Cycle sort column
  S           Reverse sort order
  /           Search/filter connections
  Escape      Clear search / close help

Export
  e           Export CSV snapshot
  r           Generate report

General
  ?           Toggle this help
  q           Quit`

	return helpOverlayStyle.Width(width / 2).Render(help)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
