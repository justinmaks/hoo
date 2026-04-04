package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/justinmaks/hoo/internal/aggregate"
	"github.com/justinmaks/hoo/internal/decode"
	"github.com/justinmaks/hoo/internal/resolve"
)

// openPort groups connections listening on a local port.
type openPort struct {
	port      uint16
	proto     string
	appProto  decode.Protocol
	peers     []peerInfo
	bytesIn   uint64
	bytesOut  uint64
	connCount int
}

type peerInfo struct {
	remoteAddr string
	hostname   string
	bytes      uint64
	state      string
}

func renderOpenPorts(conns []aggregate.Connection, width, height int, cursor int, resolver *resolve.Resolver) string {
	// Group by local port.
	portMap := make(map[uint16]*openPort)
	for _, c := range conns {
		if c.Direction != decode.DirectionInbound {
			continue
		}
		p, ok := portMap[c.LocalPort]
		if !ok {
			p = &openPort{
				port:     c.LocalPort,
				proto:    c.Key.Proto,
				appProto: c.Protocol,
			}
			portMap[c.LocalPort] = p
		}
		p.bytesIn += c.BytesIn
		p.bytesOut += c.BytesOut
		p.connCount++

		remoteIP := ""
		if c.RemoteIP != nil {
			remoteIP = c.RemoteIP.String()
		}
		hostname := remoteIP
		if resolver != nil && remoteIP != "" {
			if h := resolver.Lookup(remoteIP); h != remoteIP {
				hostname = h
			}
		}

		state := ""
		if c.Key.Proto == "TCP" {
			state = c.TCPState.String()
		}

		p.peers = append(p.peers, peerInfo{
			remoteAddr: fmt.Sprintf("%s:%d", remoteIP, c.RemotePort),
			hostname:   hostname,
			bytes:      c.BytesIn + c.BytesOut,
			state:      state,
		})
	}

	// Sort ports by total bytes descending.
	ports := make([]*openPort, 0, len(portMap))
	for _, p := range portMap {
		// Sort peers within each port.
		sort.Slice(p.peers, func(i, j int) bool {
			return p.peers[i].bytes > p.peers[j].bytes
		})
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].bytesIn+ports[i].bytesOut > ports[j].bytesIn+ports[j].bytesOut
	})

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("Open Ports"))
	sb.WriteString(fmt.Sprintf("  (%d ports receiving connections)", len(ports)))
	sb.WriteByte('\n')
	sb.WriteByte('\n')

	if len(ports) == 0 {
		sb.WriteString(dimStyle.Render("  No inbound connections detected\n"))
		return sb.String()
	}

	maxRows := height - 4
	row := 0

	for _, p := range ports {
		if row >= maxRows {
			break
		}

		// Port header line.
		portLabel := fmt.Sprintf("  :%d", p.port)
		protoLabel := string(p.appProto)
		if protoLabel == "Other" {
			protoLabel = p.proto
		}

		header := fmt.Sprintf("%-8s %-8s  %d peers  ↓%s ↑%s",
			portLabel, protoLabel, p.connCount,
			formatBytes(p.bytesIn), formatBytes(p.bytesOut))

		if row == cursor {
			sb.WriteString(selectedRowStyle.Render(header))
		} else {
			sb.WriteString(headerStyle.Render(header))
		}
		sb.WriteByte('\n')
		row++

		// Show up to 5 peers per port.
		shown := 0
		for _, peer := range p.peers {
			if row >= maxRows || shown >= 5 {
				break
			}
			display := peer.hostname
			if display == "" {
				display = peer.remoteAddr
			}

			line := fmt.Sprintf("    ├─ %-35s %10s  %s",
				truncate(display, 35), formatBytes(peer.bytes), peer.state)

			sb.WriteString(dimStyle.Render(line))
			sb.WriteByte('\n')
			row++
			shown++
		}

		if len(p.peers) > 5 {
			sb.WriteString(dimStyle.Render(fmt.Sprintf("    └─ ... and %d more\n", len(p.peers)-5)))
			row++
		}
		sb.WriteByte('\n')
		row++
	}

	return sb.String()
}

func renderDirectionalTable(conns []aggregate.Connection, dir decode.Direction, width, height int, cursor int, resolver *resolve.Resolver) string {
	label := "Inbound"
	arrow := "←"
	if dir == decode.DirectionOutbound {
		label = "Outbound"
		arrow = "→"
	}

	// Filter by direction.
	var filtered []aggregate.Connection
	for _, c := range conns {
		if c.Direction == dir {
			filtered = append(filtered, c)
		}
	}

	// Sort by bytes descending.
	sort.Slice(filtered, func(i, j int) bool {
		return (filtered[i].BytesIn + filtered[i].BytesOut) > (filtered[j].BytesIn + filtered[j].BytesOut)
	})

	var sb strings.Builder
	sb.WriteString(titleStyle.Render(fmt.Sprintf("%s Traffic", label)))

	var totalBytes uint64
	for _, c := range filtered {
		totalBytes += c.BytesIn + c.BytesOut
	}
	sb.WriteString(fmt.Sprintf("  (%d connections, %s total)", len(filtered), formatBytes(totalBytes)))
	sb.WriteByte('\n')

	if len(filtered) == 0 {
		sb.WriteString(dimStyle.Render(fmt.Sprintf("  No %s traffic\n", strings.ToLower(label))))
		return sb.String()
	}

	// Dynamic column widths.
	addrW := (width - 5 - 3 - 10 - 11 - 12) / 2
	if addrW < 16 {
		addrW = 16
	}
	if addrW > 38 {
		addrW = 38
	}

	fmtStr := fmt.Sprintf("%%-%ds %%3s %%-%ds %%-%ds %%10s %%-%ds", 5, addrW, addrW, 11)

	header := fmt.Sprintf(fmtStr, "Proto", " ", "Local", "Remote", "Bytes", "State")
	sb.WriteString(headerStyle.Render(header))
	sb.WriteByte('\n')

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

		localAddr := fmt.Sprintf("%s:%d", c.LocalIP, c.LocalPort)
		if c.LocalIP == nil {
			localAddr = fmt.Sprintf(":%d", c.LocalPort)
		}

		remoteIP := ""
		if c.RemoteIP != nil {
			remoteIP = c.RemoteIP.String()
		}
		remoteDisplay := remoteIP
		if resolver != nil && remoteIP != "" {
			if h := resolver.Lookup(remoteIP); h != remoteIP {
				remoteDisplay = h
			}
		}
		remoteAddr := fmt.Sprintf("%s:%d", truncate(remoteDisplay, addrW-7), c.RemotePort)

		totalBytes := c.BytesIn + c.BytesOut
		state := ""
		if c.Key.Proto == "TCP" {
			state = c.TCPState.String()
		}

		row := fmt.Sprintf(fmtStr,
			c.Key.Proto, arrow,
			truncate(localAddr, addrW), truncate(remoteAddr, addrW),
			formatBytes(totalBytes), state)

		if i == cursor {
			sb.WriteString(selectedRowStyle.Render(row))
		} else {
			sb.WriteString(row)
		}
		sb.WriteByte('\n')
	}

	return sb.String()
}
