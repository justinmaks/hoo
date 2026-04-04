package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("8")).
			Padding(0, 1)

	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("8")).
			Foreground(lipgloss.Color("15")).
			Padding(0, 1)

	alertStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("1")).
			Bold(true)

	pausedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("3")).
			Bold(true)

	sparkRXStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("2"))

	sparkTXStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("4"))

	selectedRowStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("8")).
				Foreground(lipgloss.Color("15"))

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("14"))

	helpOverlayStyle = lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(lipgloss.Color("12")).
				Padding(1, 2).
				Align(lipgloss.Center)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))
)
