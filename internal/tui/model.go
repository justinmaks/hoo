package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/justinmaks/hoo/internal/aggregate"
	"github.com/justinmaks/hoo/internal/anomaly"
	"github.com/justinmaks/hoo/internal/capture"
	"github.com/justinmaks/hoo/internal/decode"
	"github.com/justinmaks/hoo/internal/resolve"
)

// FocusedView represents which panel is expanded.
type FocusedView int

const (
	ViewAll FocusedView = iota
	ViewBandwidth
	ViewConnections
	ViewProtocols
	ViewNetMap
	ViewOpenPorts
	ViewInbound
	ViewOutbound
)

// tickMsg triggers periodic TUI refresh.
type tickMsg time.Time

// Model is the BubbleTea app model.
type Model struct {
	aggregator *aggregate.Aggregator
	detector   *anomaly.Detector
	resolver   *resolve.Resolver
	engine     capture.CaptureEngine
	filter     string
	localIP    string
	iface      string

	width  int
	height int

	// State.
	paused     bool
	showHelp   bool
	focusedView FocusedView
	sortCol    SortColumn
	sortDesc   bool
	cursor     int
	searching  bool
	searchTerm string
	tickRate   time.Duration

	// Status message (shown briefly after export/report).
	statusMsg     string
	statusExpires time.Time

	// Callbacks for export/report.
	OnExport func() string // returns filepath or error message
	OnReport func() string
	OnQuit   func()
}

// NewModel creates a new TUI model.
func NewModel(agg *aggregate.Aggregator, det *anomaly.Detector, res *resolve.Resolver, eng capture.CaptureEngine, filter string, tickHz int, localIP string, iface string) Model {
	if tickHz <= 0 {
		tickHz = 1
	}
	if tickHz > 10 {
		tickHz = 10
	}

	return Model{
		aggregator:  agg,
		detector:    det,
		resolver:    res,
		engine:      eng,
		filter:      filter,
		localIP:     localIP,
		iface:       iface,
		tickRate:    time.Second / time.Duration(tickHz),
		focusedView: ViewNetMap, // default to network map view
	}
}

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(m.tickRate), tea.EnterAltScreen)
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		// Clear expired status message.
		if m.statusMsg != "" && time.Now().After(m.statusExpires) {
			m.statusMsg = ""
		}
		return m, tickCmd(m.tickRate)

	case tea.KeyMsg:
		// When searching, handle search input.
		if m.searching {
			return m.handleSearchKey(msg)
		}

		switch msg.String() {
		case "q":
			if m.OnQuit != nil {
				m.OnQuit()
			}
			return m, tea.Quit

		case "?":
			m.showHelp = !m.showHelp
			return m, nil

		case "p":
			m.paused = !m.paused
			return m, nil

		case "s":
			m.sortCol = (m.sortCol + 1) % sortColumnCount
			return m, nil

		case "S":
			m.sortDesc = !m.sortDesc
			return m, nil

		case "/":
			m.searching = true
			m.searchTerm = ""
			return m, nil

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil

		case "down", "j":
			m.cursor++
			return m, nil

		case "1":
			if m.focusedView == ViewBandwidth {
				m.focusedView = ViewAll
			} else {
				m.focusedView = ViewBandwidth
			}
			return m, nil

		case "2":
			if m.focusedView == ViewConnections {
				m.focusedView = ViewAll
			} else {
				m.focusedView = ViewConnections
			}
			return m, nil

		case "3":
			if m.focusedView == ViewProtocols {
				m.focusedView = ViewAll
			} else {
				m.focusedView = ViewProtocols
			}
			return m, nil

		case "4":
			if m.focusedView == ViewNetMap {
				m.focusedView = ViewAll
			} else {
				m.focusedView = ViewNetMap
			}
			return m, nil

		case "5":
			if m.focusedView == ViewOpenPorts {
				m.focusedView = ViewAll
			} else {
				m.focusedView = ViewOpenPorts
			}
			return m, nil

		case "6":
			if m.focusedView == ViewInbound {
				m.focusedView = ViewAll
			} else {
				m.focusedView = ViewInbound
			}
			return m, nil

		case "7":
			if m.focusedView == ViewOutbound {
				m.focusedView = ViewAll
			} else {
				m.focusedView = ViewOutbound
			}
			return m, nil

		case "e":
			if m.OnExport != nil {
				m.statusMsg = m.OnExport()
				m.statusExpires = time.Now().Add(5 * time.Second)
			}
			return m, nil

		case "r":
			if m.OnReport != nil {
				m.statusMsg = m.OnReport()
				m.statusExpires = time.Now().Add(5 * time.Second)
			}
			return m, nil

		case "esc", "escape":
			m.showHelp = false
			m.searchTerm = ""
			return m, nil
		}
	}

	return m, nil
}

func (m Model) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc", "escape":
		m.searching = false
		if msg.String() != "enter" {
			m.searchTerm = ""
		}
		return m, nil
	case "backspace":
		if len(m.searchTerm) > 0 {
			m.searchTerm = m.searchTerm[:len(m.searchTerm)-1]
		}
		return m, nil
	default:
		if len(msg.String()) == 1 {
			m.searchTerm += msg.String()
		}
		return m, nil
	}
}

// View renders the UI.
func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	if m.aggregator == nil {
		return "No aggregator configured"
	}
	snap := m.aggregator.ReadSnapshot()
	if snap == nil {
		return "Waiting for data..."
	}

	// Get alert info.
	var alertCount int
	var lastAlert string
	if m.detector != nil {
		alertCount = m.detector.AlertCount()
		if alerts := m.detector.Alerts(); len(alerts) > 0 {
			lastAlert = alerts[len(alerts)-1].Summary
		}
	}

	var dropCount uint64
	if m.engine != nil {
		stats := m.engine.GetStats()
		dropCount = stats.PacketsDropped + stats.AppDropped
	}

	// Render status bar (always at bottom).
	statusBar := renderStatusBar(m.width, m.filter, m.paused, dropCount, alertCount, lastAlert)

	if m.statusMsg != "" {
		statusBar = statusBarStyle.Width(m.width).Render(m.statusMsg)
	} else if m.searching {
		statusBar = statusBarStyle.Width(m.width).Render(fmt.Sprintf("Search: %s█", m.searchTerm))
	}

	contentHeight := m.height - 2 // status bar + border

	// Help overlay.
	if m.showHelp {
		help := renderHelp(m.width, m.height)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, help)
	}

	panelWidth := m.width - 2 // account for panel borders

	var content string

	switch m.focusedView {
	case ViewBandwidth:
		content = panelStyle.Width(panelWidth).Render(
			renderSparkline(snap.Bandwidth, panelWidth-4, snap.TotalBytesIn, snap.TotalBytesOut))

	case ViewConnections:
		content = panelStyle.Width(panelWidth).Height(contentHeight).Render(
			renderConnectionTable(snap.Connections, panelWidth-4, contentHeight-2, m.cursor, m.sortCol, m.sortDesc, m.searchTerm, m.resolver))

	case ViewProtocols:
		content = panelStyle.Width(panelWidth).Render(
			renderProtocolBreakdown(snap.Protocols, panelWidth-4))

	case ViewNetMap:
		var alertList []anomaly.Alert
		if m.detector != nil {
			alertList = m.detector.Alerts()
		}
		content = renderNetMap(snap, alertList, m.resolver, m.localIP, m.iface, m.width, contentHeight)

	case ViewOpenPorts:
		content = panelStyle.Width(panelWidth).Height(contentHeight).MaxHeight(contentHeight).Render(
			renderOpenPorts(snap.Connections, panelWidth-4, contentHeight-2, m.cursor, m.resolver))

	case ViewInbound:
		content = panelStyle.Width(panelWidth).Height(contentHeight).MaxHeight(contentHeight).Render(
			renderDirectionalTable(snap.Connections, decode.DirectionInbound, panelWidth-4, contentHeight-2, m.cursor, m.resolver))

	case ViewOutbound:
		content = panelStyle.Width(panelWidth).Height(contentHeight).MaxHeight(contentHeight).Render(
			renderDirectionalTable(snap.Connections, decode.DirectionOutbound, panelWidth-4, contentHeight-2, m.cursor, m.resolver))

	default: // ViewAll
		halfWidth := panelWidth/2 - 1

		// Fixed layout: bandwidth (6 lines) + bottom (12 lines) + rest for connections.
		// Panel border adds 2 to height.
		bwInner := 4  // sparkline content lines
		bwHeight := bwInner + 2
		bottomInner := 10
		bottomHeight := bottomInner + 2
		connHeight := contentHeight - bwHeight - bottomHeight
		if connHeight < 6 {
			connHeight = 6
		}

		// Top row: bandwidth sparkline.
		bandwidth := panelStyle.Width(panelWidth).Height(bwHeight).MaxHeight(bwHeight).Render(
			renderSparkline(snap.Bandwidth, panelWidth-4, snap.TotalBytesIn, snap.TotalBytesOut))

		// Middle row: connection table.
		connections := panelStyle.Width(panelWidth).Height(connHeight).MaxHeight(connHeight).Render(
			renderConnectionTable(snap.Connections, panelWidth-4, connHeight-2, m.cursor, m.sortCol, m.sortDesc, m.searchTerm, m.resolver))

		// Bottom row: protocols + top talkers side by side (fixed height).
		protocols := panelStyle.Width(halfWidth).Height(bottomHeight).MaxHeight(bottomHeight).Render(
			renderProtocolBreakdown(snap.Protocols, halfWidth-4))
		topTalkers := panelStyle.Width(halfWidth).Height(bottomHeight).MaxHeight(bottomHeight).Render(
			renderTopTalkers(snap.TopTalkers, m.resolver))

		bottomRow := lipgloss.JoinHorizontal(lipgloss.Top, protocols, topTalkers)

		content = lipgloss.JoinVertical(lipgloss.Left, bandwidth, connections, bottomRow)
	}

	return lipgloss.JoinVertical(lipgloss.Left, content, statusBar)
}
