package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const maxEvents = 500

type teaMsg interface{}

type model struct {
	events  []connectionEvent
	pending []connectionEvent
	total   int
	paused  bool
	scroll  int
	width   int
	height  int
	err     error
}

var (
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
	accentStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	mutedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	rowStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
)

func newModel() model {
	return model{}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case " ":
			m.paused = !m.paused
			if !m.paused && len(m.pending) > 0 {
				for _, event := range m.pending {
					m.events = appendCapped(m.events, event)
				}
				m.pending = nil
				m.scroll = clampScroll(m.scroll, len(m.events), m.tableHeight())
			}
		case "c":
			m.events = nil
			m.pending = nil
			m.total = 0
			m.scroll = 0
			m.err = nil
		case "up", "k":
			m.scroll = clampScroll(m.scroll+1, len(m.events), m.tableHeight())
		case "down", "j":
			m.scroll = clampScroll(m.scroll-1, len(m.events), m.tableHeight())
		case "pgup":
			m.scroll = clampScroll(m.scroll+m.tableHeight(), len(m.events), m.tableHeight())
		case "pgdown":
			m.scroll = clampScroll(m.scroll-m.tableHeight(), len(m.events), m.tableHeight())
		case "home":
			m.scroll = clampScroll(len(m.events), len(m.events), m.tableHeight())
		case "end":
			m.scroll = 0
		}
	case connectionMsg:
		m.total++
		event := connectionEvent(msg)
		if m.paused {
			m.pending = appendCapped(m.pending, event)
			return m, nil
		}
		m.events = appendCapped(m.events, event)
		m.scroll = clampScroll(m.scroll, len(m.events), m.tableHeight())
	case collectorErrMsg:
		m.err = msg.err
	}

	return m, nil
}

func (m model) View() string {
	if m.width == 0 {
		return ""
	}

	parts := []string{
		m.header(),
		m.table(),
		m.footer(),
	}
	if m.err != nil {
		parts = append(parts, errorStyle.Render(m.err.Error()))
	}

	return strings.Join(parts, "\n")
}

func (m model) header() string {
	status := accentStyle.Render("running")
	if m.paused {
		status = mutedStyle.Render("paused")
	}

	left := headerStyle.Render("visualiser")
	right := fmt.Sprintf(
		"%s  total %d  visible %d",
		status,
		m.total,
		len(m.events),
	)
	if len(m.pending) > 0 {
		right += fmt.Sprintf("  buffered %d", len(m.pending))
	}

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}

	return left + strings.Repeat(" ", gap) + right
}

func (m model) table() string {
	tableHeight := m.tableHeight()
	widths := m.columnWidths()

	lines := make([]string, 0, tableHeight+2)
	lines = append(lines, mutedStyle.Render(formatRow(widths, "PROCESS", "SOURCE", "DESTINATION", "DPORT", "TIME")))
	lines = append(lines, mutedStyle.Render(strings.Repeat("-", min(m.width, sumWidths(widths)+8))))

	visible := visibleEvents(m.events, tableHeight, m.scroll)
	for _, event := range visible {
		source := fmt.Sprintf("%s:%d", event.SrcIP, event.SrcPort)
		destination := event.DstIP
		lines = append(lines, rowStyle.Render(formatRow(
			widths,
			event.Process,
			source,
			destination,
			fmt.Sprintf("%d", event.DstPort),
			event.Time.Format("15:04:05"),
		)))
	}

	for len(lines) < tableHeight+2 {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func (m model) footer() string {
	footer := "q quit  c clear  space pause  up/down scroll"
	if m.paused {
		footer = "q quit  c clear  space resume  up/down scroll"
	}
	if m.scroll > 0 {
		footer += fmt.Sprintf("  offset %d", m.scroll)
	}
	return mutedStyle.Render(footer)
}

func (m model) tableHeight() int {
	height := m.height - 5
	if height < 1 {
		return 1
	}
	return height
}

func (m model) columnWidths() [5]int {
	width := m.width
	if width < 80 {
		width = 80
	}

	process := 16
	dport := 6
	timestamp := 8
	spacing := 8
	remaining := width - process - dport - timestamp - spacing
	if remaining < 38 {
		remaining = 38
	}

	source := remaining / 2
	destination := remaining - source
	return [5]int{process, source, destination, dport, timestamp}
}

func formatRow(widths [5]int, process, source, destination, dport, timestamp string) string {
	return fmt.Sprintf(
		"%-*s  %-*s  %-*s  %*s  %-*s",
		widths[0], truncate(process, widths[0]),
		widths[1], truncate(source, widths[1]),
		widths[2], truncate(destination, widths[2]),
		widths[3], truncate(dport, widths[3]),
		widths[4], truncate(timestamp, widths[4]),
	)
}

func visibleEvents(events []connectionEvent, height, scroll int) []connectionEvent {
	if len(events) == 0 || height <= 0 {
		return nil
	}

	end := len(events) - scroll
	if end < 0 {
		end = 0
	}
	start := end - height
	if start < 0 {
		start = 0
	}

	return events[start:end]
}

func appendCapped(events []connectionEvent, event connectionEvent) []connectionEvent {
	events = append(events, event)
	if len(events) <= maxEvents {
		return events
	}
	copy(events, events[len(events)-maxEvents:])
	return events[:maxEvents]
}

func clampScroll(scroll, total, height int) int {
	if scroll < 0 {
		return 0
	}
	maxScroll := total - height
	if maxScroll < 0 {
		maxScroll = 0
	}
	if scroll > maxScroll {
		return maxScroll
	}
	return scroll
}

func truncate(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	if width == 1 {
		return "."
	}
	runes := []rune(value)
	for len(runes) > 0 && lipgloss.Width(string(runes))+1 > width {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "."
}

func sumWidths(widths [5]int) int {
	total := 0
	for _, width := range widths {
		total += width
	}
	return total
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
