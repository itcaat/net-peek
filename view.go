package main

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m model) View() string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	keyStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	valueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	boxStyle := lipgloss.NewStyle().Padding(0, 1)

	direction := "asc"
	if m.sortDesc {
		direction = "desc"
	}
	state := "running"
	if m.paused {
		state = "paused"
	}
	totalInRate, totalOutRate := m.totalRates()
	primary := strings.Join([]string{
		titleStyle.Render("net-peek"),
		mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
		mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
		mutedStyle.Render("state") + " " + valueStyle.Render(state),
		mutedStyle.Render("avg") + " " + valueStyle.Render(m.avgWindow().String()),
		mutedStyle.Render("rate") + " " + valueStyle.Render("in "+humanMbitRate(totalInRate)+" out "+humanMbitRate(totalOutRate)),
		mutedStyle.Render("sorted") + " " + valueStyle.Render(m.sortField.String()+" "+direction),
	}, "  ")
	if m.mode == modeGateway {
		parts := []string{
			titleStyle.Render("net-peek"),
			mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
			mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
			mutedStyle.Render("state") + " " + valueStyle.Render(state),
			mutedStyle.Render("avg") + " " + valueStyle.Render(m.avgWindow().String()),
			mutedStyle.Render("rate") + " " + valueStyle.Render("in "+humanMbitRate(totalInRate)+" out "+humanMbitRate(totalOutRate)),
			mutedStyle.Render("sorted") + " " + valueStyle.Render(m.sortField.String()+" "+direction),
		}
		primary = strings.Join(parts, "  ")
	}
	if m.searchQuery != "" || m.searching {
		cursor := ""
		if m.searching {
			cursor = "_"
		}
		primary += "  " + mutedStyle.Render("filter") + " " + valueStyle.Render("/"+m.searchQuery+cursor)
	}
	keys := strings.Join([]string{
		hotkey(keyStyle, "enter", "open"),
		hotkey(keyStyle, "m", "mode"),
		hotkey(keyStyle, "tab", "iface"),
		hotkey(keyStyle, "/", "search"),
		hotkey(keyStyle, "space", "pause"),
		hotkey(keyStyle, "+/-", "avg"),
		hotkey(keyStyle, "q", "quit"),
	}, "  ")
	if m.searching {
		keys = strings.Join([]string{
			hotkey(keyStyle, "enter", "open"),
			hotkey(keyStyle, "esc", "clear"),
			hotkey(keyStyle, "backspace", "delete"),
			hotkey(keyStyle, "m", "mode"),
			hotkey(keyStyle, "tab", "iface"),
			hotkey(keyStyle, "space", "pause"),
			hotkey(keyStyle, "+/-", "avg"),
			hotkey(keyStyle, "ctrl+c", "quit"),
		}, "  ")
	}
	if m.inIPView() {
		primary = strings.Join([]string{
			titleStyle.Render("net-peek"),
			mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
			mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
			mutedStyle.Render("state") + " " + valueStyle.Render(state),
			mutedStyle.Render("avg") + " " + valueStyle.Render(m.avgWindow().String()),
			mutedStyle.Render("rate") + " " + valueStyle.Render("in "+humanMbitRate(totalInRate)+" out "+humanMbitRate(totalOutRate)),
			mutedStyle.Render("ip") + " " + valueStyle.Render(m.selectedIP),
		}, "  ")
		if m.mode == modeGateway {
			parts := []string{
				titleStyle.Render("net-peek"),
				mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
				mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
				mutedStyle.Render("state") + " " + valueStyle.Render(state),
				mutedStyle.Render("avg") + " " + valueStyle.Render(m.avgWindow().String()),
				mutedStyle.Render("rate") + " " + valueStyle.Render("in "+humanMbitRate(totalInRate)+" out "+humanMbitRate(totalOutRate)),
				mutedStyle.Render("ip") + " " + valueStyle.Render(m.selectedIP),
			}
			primary = strings.Join(parts, "  ")
		}
		keys = strings.Join([]string{
			hotkey(keyStyle, "backspace", "back"),
			hotkey(keyStyle, "esc", "back"),
			hotkey(keyStyle, "m", "mode"),
			hotkey(keyStyle, "tab", "iface"),
			hotkey(keyStyle, "space", "pause"),
			hotkey(keyStyle, "+/-", "avg"),
			hotkey(keyStyle, "q", "quit"),
		}, "  ")
	}
	if m.ifacePicker {
		primary = strings.Join([]string{
			titleStyle.Render("net-peek"),
			mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
			mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
			mutedStyle.Render("select interface"),
		}, "  ")
		keys = strings.Join([]string{
			hotkey(keyStyle, "up/down", "select"),
			hotkey(keyStyle, "enter", "switch"),
			hotkey(keyStyle, "esc", "close"),
			hotkey(keyStyle, "tab", "close"),
			hotkey(keyStyle, "q", "quit"),
		}, "  ")
		header := primary + "\n" + keys
		return boxStyle.Render(header + "\n\n" + m.renderIfacePicker(mutedStyle, valueStyle))
	}
	header := primary + "\n" + keys
	body := m.table.View()

	status := mutedStyle.Render("capturing packets; totals are since start")
	if m.mode == modeGateway {
		status = mutedStyle.Render("gateway mode aggregates captured packets by endpoint IP; connections are local sockets only")
	}
	if m.inIPView() {
		stat := m.stats[m.selectedIP]
		if stat != nil {
			status = mutedStyle.Render("connections: " + strconv.Itoa(len(m.connections[m.selectedIP])) + " | in: " + humanBytes(float64(stat.InBytes)) + " | out: " + humanBytes(float64(stat.OutBytes)) + " | rate: " + humanBitRate(stat.TotalRate()))
		} else {
			status = mutedStyle.Render("no traffic stats for selected IP yet")
		}
	}
	if len(m.errs) > 0 {
		status = warnStyle.Render(strings.Join(m.errs, " | "))
	}
	if len(m.stats) == 0 && !m.inIPView() {
		status += "\n" + mutedStyle.Render("No packets yet. Try running as root or choose a busy interface.")
	}
	if m.inIPView() && len(m.connections[m.selectedIP]) == 0 {
		status += "\n" + mutedStyle.Render("No established connections for this IP right now.")
	}

	return boxStyle.Render(header + "\n\n" + body + "\n\n" + status)
}

func (m model) renderIfacePicker(mutedStyle, valueStyle lipgloss.Style) string {
	lines := make([]string, 0, len(m.ifaceList)+1)
	limit := min(len(m.ifaceList), max(8, m.height-6))
	start := 0
	if m.ifaceIndex >= limit {
		start = m.ifaceIndex - limit + 1
	}
	for i := start; i < len(m.ifaceList) && i < start+limit; i++ {
		prefix := "  "
		nameStyle := mutedStyle
		if i == m.ifaceIndex {
			prefix = "> "
			nameStyle = valueStyle
		}
		current := ""
		if m.ifaceList[i] == m.iface {
			current = mutedStyle.Render(" current")
		}
		lines = append(lines, prefix+nameStyle.Render(m.ifaceList[i])+current)
	}
	if len(m.ifaceList) > limit {
		lines = append(lines, mutedStyle.Render("..."))
	}
	return strings.Join(lines, "\n")
}

func hotkey(style lipgloss.Style, key, label string) string {
	return style.Render(key) + " " + label
}
