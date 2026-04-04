package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/justinmaks/hoo/internal/aggregate"
	"github.com/justinmaks/hoo/internal/anomaly"
	"github.com/justinmaks/hoo/internal/decode"
	"github.com/justinmaks/hoo/internal/resolve"
)

// Protocol colors for the map.
var protoColors = map[decode.Protocol]lipgloss.Color{
	decode.ProtoHTTPS: lipgloss.Color("2"),  // green
	decode.ProtoHTTP:  lipgloss.Color("4"),  // blue
	decode.ProtoDNS:   lipgloss.Color("3"),  // yellow
	decode.ProtoSSH:   lipgloss.Color("5"),  // magenta
	decode.ProtoOther: lipgloss.Color("8"),  // gray
}

var (
	alertNodeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("1")).
			Bold(true)

	normalNodeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15"))

	centerNodeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("6"))

	legendStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))
)

// remoteNode groups connections to a single remote host.
type remoteNode struct {
	ip          string
	hostname    string
	proto       decode.Protocol
	transport   string
	totalBytes  uint64
	connCount   int
	ports       []uint16
	isAnomalous bool
	alertMsg    string
	direction   decode.Direction
}

func renderNetMap(snap *aggregate.Snapshot, alerts []anomaly.Alert, resolver *resolve.Resolver, localIP string, iface string, width, height int) string {
	if width < 40 || height < 15 {
		return "Terminal too small for network map"
	}

	// Build remote nodes from connections.
	nodeMap := make(map[string]*remoteNode)
	for _, c := range snap.Connections {
		if c.RemoteIP == nil {
			continue
		}
		ip := c.RemoteIP.String()

		key := ip
		n, ok := nodeMap[key]
		if !ok {
			hostname := ip
			if resolver != nil {
				hostname = resolver.Lookup(ip)
			}
			n = &remoteNode{
				ip:        ip,
				hostname:  hostname,
				proto:     c.Protocol,
				transport: c.Key.Proto,
				direction: c.Direction,
			}
			nodeMap[key] = n
		}
		n.totalBytes += c.BytesIn + c.BytesOut
		n.connCount++
		n.ports = appendUnique(n.ports, c.RemotePort)
	}

	// Mark anomalous nodes.
	alertedIPs := make(map[string]string)
	for _, a := range alerts {
		// Extract IP from alert summary if possible.
		for ip := range nodeMap {
			if strings.Contains(a.Summary, ip) || strings.Contains(a.Details, ip) {
				alertedIPs[ip] = a.Summary
			}
		}
		// Also flag unexpected protocol alerts.
		if a.Type == anomaly.AlertUnexpectedProtocol {
			for ip, n := range nodeMap {
				if n.proto == decode.ProtoOther {
					alertedIPs[ip] = a.Summary
				}
			}
		}
	}
	for ip, msg := range alertedIPs {
		if n, ok := nodeMap[ip]; ok {
			n.isAnomalous = true
			n.alertMsg = msg
		}
	}

	// Sort nodes by bandwidth descending.
	nodes := make([]*remoteNode, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].totalBytes > nodes[j].totalBytes
	})

	// Limit visible nodes.
	maxNodes := (height - 8) / 3
	if maxNodes < 4 {
		maxNodes = 4
	}
	if maxNodes > 20 {
		maxNodes = 20
	}
	if len(nodes) > maxNodes {
		nodes = nodes[:maxNodes]
	}

	// Render on a character grid.
	grid := newCharGrid(width, height-2) // leave room for legend

	// Place center node.
	centerX := width / 4
	centerY := height / 2

	centerLabel := fmt.Sprintf("┌─── YOU ───────────────┐")
	centerLine2 := fmt.Sprintf("│  %s", padRight(iface, 21))
	centerLine3 := fmt.Sprintf("│  %s", padRight(localIP, 21))
	centerLine4 := fmt.Sprintf("│  %s", padRight(fmt.Sprintf("%d connections", snap.ActiveConns), 21))
	centerLine5 := fmt.Sprintf("│  ↓%s ↑%s", padRight(formatBytes(snap.TotalBytesIn), 8), padRight(formatBytes(snap.TotalBytesOut), 8))
	centerClose := fmt.Sprintf("└───────────────────────┘")

	cy := centerY - 3
	grid.putStyled(centerX-12, cy, centerLabel, centerNodeStyle)
	grid.putStyled(centerX-12, cy+1, centerLine2+"│", centerNodeStyle)
	grid.putStyled(centerX-12, cy+2, centerLine3+"│", centerNodeStyle)
	grid.putStyled(centerX-12, cy+3, centerLine4+"│", centerNodeStyle)
	grid.putStyled(centerX-12, cy+4, centerLine5+"│", centerNodeStyle)
	grid.putStyled(centerX-12, cy+5, centerClose, centerNodeStyle)

	// Place remote nodes radially on the right side.
	rightX := width * 3 / 5
	if rightX < centerX+30 {
		rightX = centerX + 30
	}

	nodeSpacing := 1
	if len(nodes) > 0 {
		nodeSpacing = (height - 4) / len(nodes)
		if nodeSpacing < 3 {
			nodeSpacing = 3
		}
	}

	startY := 1
	if len(nodes)*nodeSpacing < height-4 {
		startY = (height - 4 - len(nodes)*nodeSpacing) / 2
	}

	for i, n := range nodes {
		ny := startY + i*nodeSpacing
		if ny >= height-4 {
			break
		}

		// Draw connection line from center to node.
		lineY := ny + 1
		lineStartX := centerX + 12
		lineEndX := rightX - 1

		// Choose line style based on bandwidth.
		lineChar := "─"
		if n.totalBytes > 1<<20 { // > 1MB
			lineChar = "═"
		}
		if n.isAnomalous {
			lineChar = "!"
		}

		// Protocol label on the line.
		protoLabel := fmt.Sprintf(" %s ", string(n.proto))
		color, ok := protoColors[n.proto]
		if !ok {
			color = lipgloss.Color("8")
		}
		lineStyle := lipgloss.NewStyle().Foreground(color)
		if n.isAnomalous {
			lineStyle = alertNodeStyle
		}

		// Draw the line.
		midX := (lineStartX + lineEndX) / 2
		for x := lineStartX; x < lineEndX; x++ {
			if x >= midX-len(protoLabel)/2 && x < midX+len(protoLabel)/2+1 {
				continue // leave space for label
			}
			grid.putStyled(x, lineY, lineChar, lineStyle)
		}

		// Arrow head.
		arrowDir := "►"
		if n.direction == decode.DirectionInbound {
			arrowDir = "◄"
			grid.putStyled(lineStartX, lineY, arrowDir, lineStyle)
		} else {
			grid.putStyled(lineEndX, lineY, arrowDir, lineStyle)
		}

		// Protocol label.
		grid.putStyled(midX-len(protoLabel)/2, lineY, protoLabel, lineStyle)

		// Rate label on line.
		rateLabel := fmt.Sprintf(" %s/s ", formatBytes(n.totalBytes))
		grid.putStyled(midX-len(rateLabel)/2, lineY-1, rateLabel, dimStyle)

		// Draw remote node box.
		nodeStyle := normalNodeStyle
		if n.isAnomalous {
			nodeStyle = alertNodeStyle
		}

		displayName := n.hostname
		if displayName == n.ip && resolver != nil {
			displayName = n.ip
		}

		// Build port list.
		portStr := ""
		if len(n.ports) <= 3 {
			parts := make([]string, len(n.ports))
			for j, p := range n.ports {
				parts[j] = fmt.Sprintf("%d", p)
			}
			portStr = strings.Join(parts, ",")
		} else {
			portStr = fmt.Sprintf("%d ports", len(n.ports))
		}

		// Node box.
		boxWidth := max(len(displayName)+4, len(n.ip)+len(portStr)+5, 20)
		if n.isAnomalous {
			boxWidth = max(boxWidth, len(n.alertMsg)+4)
		}
		if rightX+boxWidth >= width {
			boxWidth = width - rightX - 1
		}

		prefix := "┌"
		suffix := "┐"
		if n.isAnomalous {
			prefix = "┌⚠"
			suffix = "⚠┐"
		}

		topBorder := prefix + strings.Repeat("─", boxWidth-2) + suffix
		botBorder := "└" + strings.Repeat("─", boxWidth-2) + "┘"

		grid.putStyled(rightX, ny, topBorder, nodeStyle)
		grid.putStyled(rightX, ny+1, "│ "+padRight(truncate(displayName, boxWidth-4), boxWidth-4)+" │", nodeStyle)
		grid.putStyled(rightX, ny+2, "│ "+padRight(fmt.Sprintf("%s :%s", n.ip, portStr), boxWidth-4)+" │", nodeStyle)

		rowIdx := 3
		if n.connCount > 1 {
			connInfo := fmt.Sprintf("%d conns, %s", n.connCount, formatBytes(n.totalBytes))
			grid.putStyled(rightX, ny+rowIdx, "│ "+padRight(truncate(connInfo, boxWidth-4), boxWidth-4)+" │", nodeStyle)
			rowIdx++
		}

		if n.isAnomalous && n.alertMsg != "" {
			grid.putStyled(rightX, ny+rowIdx, "│ "+padRight(truncate(n.alertMsg, boxWidth-4), boxWidth-4)+" │", alertNodeStyle)
			rowIdx++
		}

		grid.putStyled(rightX, ny+rowIdx, botBorder, nodeStyle)
	}

	// Render the grid.
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("  Network Map"))
	sb.WriteString(fmt.Sprintf("  %d hosts visible", len(nodes)))
	if len(nodeMap) > len(nodes) {
		sb.WriteString(fmt.Sprintf(" (%d total)", len(nodeMap)))
	}
	sb.WriteByte('\n')
	sb.WriteString(grid.render())

	// Legend.
	legend := []string{}
	for _, proto := range decode.AllProtocols() {
		c := protoColors[proto]
		s := lipgloss.NewStyle().Foreground(c)
		legend = append(legend, s.Render(fmt.Sprintf("■ %s", string(proto))))
	}
	legend = append(legend, alertNodeStyle.Render("! ANOMALY"))
	sb.WriteString(legendStyle.Render("  " + strings.Join(legend, "   ")))

	return sb.String()
}

// charGrid is a simple 2D character buffer for placing styled text.
// Uses integer style IDs to avoid comparing lipgloss.Style structs directly.
type charGrid struct {
	cells    [][]rune
	styleIDs [][]int
	palette  []lipgloss.Style
	idMap    map[string]int // renderer string -> ID
	width    int
	height   int
}

func newCharGrid(w, h int) *charGrid {
	defaultStyle := lipgloss.NewStyle()
	cells := make([][]rune, h)
	styleIDs := make([][]int, h)
	for y := 0; y < h; y++ {
		cells[y] = make([]rune, w)
		styleIDs[y] = make([]int, w)
		for x := 0; x < w; x++ {
			cells[y][x] = ' '
		}
	}
	return &charGrid{
		cells:    cells,
		styleIDs: styleIDs,
		palette:  []lipgloss.Style{defaultStyle},
		idMap:    map[string]int{"__default__": 0},
		width:    w,
		height:   h,
	}
}

func (g *charGrid) styleID(style lipgloss.Style) int {
	// Use the style's rendered empty string as a key.
	key := style.Render("")
	if id, ok := g.idMap[key]; ok {
		return id
	}
	id := len(g.palette)
	g.palette = append(g.palette, style)
	g.idMap[key] = id
	return id
}

func (g *charGrid) putStyled(x, y int, text string, style lipgloss.Style) {
	if y < 0 || y >= g.height {
		return
	}
	id := g.styleID(style)
	runes := []rune(text)
	for i, r := range runes {
		px := x + i
		if px >= 0 && px < g.width {
			g.cells[y][px] = r
			g.styleIDs[y][px] = id
		}
	}
}

func (g *charGrid) render() string {
	var sb strings.Builder
	for y := 0; y < g.height; y++ {
		x := 0
		for x < g.width {
			sid := g.styleIDs[y][x]
			start := x
			for x < g.width && g.styleIDs[y][x] == sid {
				x++
			}
			chunk := string(g.cells[y][start:x])
			sb.WriteString(g.palette[sid].Render(chunk))
		}
		if y < g.height-1 {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func appendUnique(slice []uint16, val uint16) []uint16 {
	for _, v := range slice {
		if v == val {
			return slice
		}
	}
	return append(slice, val)
}

func padRight(s string, length int) string {
	if len(s) >= length {
		return s[:length]
	}
	return s + strings.Repeat(" ", length-len(s))
}

func max(a, b int, rest ...int) int {
	if b > a {
		a = b
	}
	for _, v := range rest {
		if v > a {
			a = v
		}
	}
	return a
}

