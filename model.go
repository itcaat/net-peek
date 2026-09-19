package main

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const connInterval = 2 * time.Second

type tickMsg time.Time
type connMsg map[string][]connection
type errMsg error

type sortField uint8

const (
	sortTotalRate sortField = iota
	sortIP
	sortConnections
	sortInRate
	sortOutRate
	sortTotalIn
	sortTotalOut
	sortTotal
)

func (f sortField) String() string {
	switch f {
	case sortIP:
		return "IP"
	case sortConnections:
		return "Conn"
	case sortInRate:
		return "In/s"
	case sortOutRate:
		return "Out/s"
	case sortTotalIn:
		return "Total In"
	case sortTotalOut:
		return "Total Out"
	case sortTotal:
		return "Total"
	default:
		return "Total rate"
	}
}

type model struct {
	capture       *captureManager
	iface         string
	mode          captureMode
	stats         map[string]*ipStats
	connections   map[string][]connection
	table         table.Model
	selectedIP    string
	sortField     sortField
	sortDesc      bool
	paused        bool
	avgIdx        int
	searching     bool
	searchQuery   string
	ifacePicker   bool
	ifaceList     []string
	ifaceIndex    int
	totalInBytes  uint64
	totalOutBytes uint64
	totalInRate   float64
	totalOutRate  float64
	totalHistory  []statSample
	errs          []string
	width         int
	height        int
	lastTick      time.Time
}

func newModel(capture *captureManager, iface string, mode captureMode) model {
	initial := model{sortField: sortTotal, sortDesc: true}
	ifaces, err := availableInterfaceNames()
	if err != nil || len(ifaces) == 0 {
		ifaces = []string{"all"}
	}
	ifaceIndex := 0
	for i, name := range ifaces {
		if name == iface {
			ifaceIndex = i
			break
		}
	}
	columns := initial.ipColumns(28)
	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(16),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).BorderBottom(true).Bold(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(false)
	t.SetStyles(s)

	return model{
		capture:     capture,
		iface:       iface,
		mode:        mode,
		stats:       map[string]*ipStats{},
		connections: map[string][]connection{},
		table:       t,
		sortField:   initial.sortField,
		sortDesc:    initial.sortDesc,
		ifaceList:   ifaces,
		ifaceIndex:  ifaceIndex,
		lastTick:    time.Now(),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.tickCmd(), connCmd())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table.SetHeight(max(5, msg.Height-9))
		m.resizeColumns()
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.capture.stop()
			return m, tea.Quit
		}
		if m.ifacePicker {
			return m.handleIfacePickerKey(msg)
		}
		if m.searching && m.handleSearchKey(msg) {
			return m, nil
		}
		switch msg.String() {
		case "q":
			m.capture.stop()
			return m, tea.Quit
		case "esc", "backspace", "left":
			if m.inIPView() {
				m.selectedIP = ""
				m.table.SetRows(nil)
				m.resizeColumns()
				m.refreshRows()
			} else if msg.String() == "esc" {
				m.capture.stop()
				return m, tea.Quit
			}
		case "enter":
			if !m.inIPView() {
				m.openSelectedIP()
			}
		case " ":
			m.paused = !m.paused
		case "+", "=":
			m.shorterAvgWindow()
		case "-", "_":
			m.longerAvgWindow()
		case "tab":
			m.openIfacePicker()
		case "m":
			m.toggleMode()
		case "/":
			if !m.inIPView() {
				m.searching = true
			}
		case "i":
			m.setSort(sortIP)
		case "c":
			m.setSort(sortConnections)
		case "r":
			m.setSort(sortInRate)
		case "o":
			m.setSort(sortOutRate)
		case "n":
			m.setSort(sortTotalIn)
		case "u":
			m.setSort(sortTotalOut)
		case "t":
			m.setSort(sortTotal)
		}
	case tickMsg:
		if !m.paused {
			m.drainEvents()
			m.updateRates(time.Time(msg))
			m.refreshRows()
		}
		return m, m.tickCmd()
	case connMsg:
		if !m.paused {
			m.connections = msg
			for ip, stat := range m.stats {
				stat.Connections = m.connections[ip]
			}
			m.refreshRows()
		}
		return m, connCmd()
	case errMsg:
		if msg != nil {
			m.errs = append(m.errs, msg.Error())
			if len(m.errs) > 4 {
				m.errs = m.errs[len(m.errs)-4:]
			}
		}
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) handleIfacePickerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.capture.stop()
		return m, tea.Quit
	case "tab", "esc":
		m.ifacePicker = false
	case "up", "k":
		if len(m.ifaceList) > 0 {
			m.ifaceIndex = (m.ifaceIndex - 1 + len(m.ifaceList)) % len(m.ifaceList)
		}
	case "down", "j":
		if len(m.ifaceList) > 0 {
			m.ifaceIndex = (m.ifaceIndex + 1) % len(m.ifaceList)
		}
	case "enter":
		m.selectIface()
	}
	return m, nil
}

func (m *model) openIfacePicker() {
	ifaces, err := availableInterfaceNames()
	if err == nil && len(ifaces) > 0 {
		m.ifaceList = ifaces
	}
	if len(m.ifaceList) == 0 {
		m.ifaceList = []string{"all"}
	}
	m.ifaceIndex = 0
	for i, name := range m.ifaceList {
		if name == m.iface {
			m.ifaceIndex = i
			break
		}
	}
	m.ifacePicker = true
}

func (m *model) selectIface() {
	if len(m.ifaceList) == 0 || m.ifaceIndex < 0 || m.ifaceIndex >= len(m.ifaceList) {
		return
	}
	nextIface := m.ifaceList[m.ifaceIndex]
	if nextIface == m.iface {
		m.ifacePicker = false
		return
	}
	if m.switchCapture(nextIface, m.mode) {
		m.ifacePicker = false
	}
}

func (m *model) toggleMode() {
	nextMode := nextCaptureMode(m.mode)
	m.switchCapture(m.iface, nextMode)
}

func nextCaptureMode(mode captureMode) captureMode {
	if mode == modeGateway {
		return modeHost
	}
	return modeGateway
}

func (m *model) switchCapture(nextIface string, nextMode captureMode) bool {
	nextCapture, err := newCaptureManagerWithMode(context.Background(), nextIface, nextMode)
	if err != nil {
		m.errs = append(m.errs, err.Error())
		if len(m.errs) > 4 {
			m.errs = m.errs[len(m.errs)-4:]
		}
		return false
	}
	m.capture.stop()
	m.capture = nextCapture
	m.iface = nextIface
	m.mode = nextMode
	m.selectedIP = ""
	m.searching = false
	m.searchQuery = ""
	m.stats = map[string]*ipStats{}
	m.connections = map[string][]connection{}
	m.totalInBytes = 0
	m.totalOutBytes = 0
	m.totalInRate = 0
	m.totalOutRate = 0
	m.totalHistory = nil
	m.lastTick = time.Now()
	m.table.SetRows(nil)
	m.resizeColumns()
	return true
}

func (m *model) handleSearchKey(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "esc":
		m.searching = false
		m.searchQuery = ""
		m.refreshRows()
		return true
	case "backspace", "ctrl+h":
		if len(m.searchQuery) > 0 {
			m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
			m.refreshRows()
			return true
		}
		return false
	case "/":
		return true
	case " ", "+", "=", "-", "_":
		return false
	default:
		if len(msg.Runes) > 0 {
			m.searchQuery += string(msg.Runes)
			m.refreshRows()
			return true
		}
	}
	return false
}

func (m model) inIPView() bool {
	return m.selectedIP != ""
}

func (m *model) openSelectedIP() {
	row := m.table.SelectedRow()
	if len(row) == 0 {
		return
	}
	ip := row[0]
	if _, ok := m.stats[ip]; !ok {
		return
	}
	m.selectedIP = ip
	m.table.SetRows(nil)
	m.resizeColumns()
	m.refreshRows()
}

func (m *model) setSort(field sortField) {
	if m.sortField == field {
		m.sortDesc = !m.sortDesc
	} else {
		m.sortField = field
		m.sortDesc = field != sortIP
	}
	m.resizeColumns()
	m.refreshRows()
}

func (m *model) shorterAvgWindow() {
	if m.avgIdx > 0 {
		m.avgIdx--
		m.updateRates(time.Now())
		m.refreshRows()
	}
}

func (m *model) longerAvgWindow() {
	if m.avgIdx < len(avgWindows)-1 {
		m.avgIdx++
		m.updateRates(time.Now())
		m.refreshRows()
	}
}

func (m model) avgWindow() time.Duration {
	if m.avgIdx < 0 || m.avgIdx >= len(avgWindows) {
		return avgWindows[0]
	}
	return avgWindows[m.avgIdx]
}

func (m *model) drainEvents() {
	for ip, delta := range m.capture.drainDeltas() {
		stat := m.stats[ip]
		if stat == nil {
			stat = &ipStats{IP: ip}
			m.stats[ip] = stat
		}
		stat.InBytes += delta.InBytes
		stat.OutBytes += delta.OutBytes
		m.totalInBytes += delta.InBytes
		m.totalOutBytes += delta.OutBytes
	}

	for {
		select {
		case err := <-m.capture.errs:
			if err != nil {
				m.errs = append(m.errs, err.Error())
			}
		default:
			return
		}
	}
}

func (m *model) updateRates(now time.Time) {
	m.totalHistory = append(m.totalHistory, statSample{At: now, InBytes: m.totalInBytes, OutBytes: m.totalOutBytes})
	m.totalHistory = trimStatHistory(m.totalHistory, now)
	m.totalInRate, m.totalOutRate = ratesForHistory(m.totalHistory, now, m.avgWindow())

	for _, stat := range m.stats {
		stat.History = append(stat.History, statSample{At: now, InBytes: stat.InBytes, OutBytes: stat.OutBytes})
		stat.trimHistory(now)
		stat.InRate, stat.OutRate = stat.ratesForWindow(now, m.avgWindow())
		stat.Connections = m.connections[stat.IP]
	}
	m.lastTick = now
}

func (m *model) refreshRows() {
	if m.inIPView() {
		m.refreshConnectionRows()
		return
	}

	stats := make([]*ipStats, 0, len(m.stats))
	for _, stat := range m.stats {
		if m.searchQuery != "" && !strings.Contains(stat.IP, m.searchQuery) {
			continue
		}
		stats = append(stats, stat)
	}
	sort.Slice(stats, func(i, j int) bool {
		cmp := compareStats(stats[i], stats[j], m.sortField)
		if cmp == 0 {
			cmp = compareStats(stats[i], stats[j], sortTotalRate)
		}
		if cmp == 0 {
			cmp = strings.Compare(stats[i].IP, stats[j].IP)
		}
		if m.sortDesc {
			return cmp > 0
		}
		return cmp < 0
	})

	rows := make([]table.Row, 0, len(stats))
	for _, stat := range stats {
		rows = append(rows, table.Row{
			stat.IP,
			strconv.Itoa(len(stat.Connections)),
			humanBitRate(stat.InRate),
			humanBitRate(stat.OutRate),
			humanBytes(float64(stat.InBytes)),
			humanBytes(float64(stat.OutBytes)),
			humanBytes(float64(stat.Total())),
		})
	}
	m.table.SetRows(rows)
}

func (m *model) refreshConnectionRows() {
	conns := append([]connection(nil), m.connections[m.selectedIP]...)
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].Remote == conns[j].Remote {
			return conns[i].Local < conns[j].Local
		}
		return conns[i].Remote < conns[j].Remote
	})

	rows := make([]table.Row, 0, len(conns))
	for _, c := range conns {
		rows = append(rows, table.Row{
			c.Proto,
			c.State,
			c.Local,
			c.Remote,
			c.PID,
		})
	}
	m.table.SetRows(rows)
}

func compareStats(a, b *ipStats, field sortField) int {
	switch field {
	case sortIP:
		return strings.Compare(a.IP, b.IP)
	case sortConnections:
		return compareInt(len(a.Connections), len(b.Connections))
	case sortInRate:
		return compareFloat(a.InRate, b.InRate)
	case sortOutRate:
		return compareFloat(a.OutRate, b.OutRate)
	case sortTotalIn:
		return compareUint(a.InBytes, b.InBytes)
	case sortTotalOut:
		return compareUint(a.OutBytes, b.OutBytes)
	case sortTotal:
		return compareUint(a.Total(), b.Total())
	default:
		return compareFloat(a.TotalRate(), b.TotalRate())
	}
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func (m *model) resizeColumns() {
	if m.width <= 0 {
		return
	}
	if m.inIPView() {
		remoteWidth := max(20, min(48, m.width-60))
		localWidth := max(18, min(42, m.width-78))
		m.table.SetColumns([]table.Column{
			{Title: "Proto", Width: 7},
			{Title: "State", Width: 13},
			{Title: "Local", Width: localWidth},
			{Title: "Remote", Width: remoteWidth},
			{Title: "Process", Width: 24},
		})
		return
	}

	ipWidth := max(18, min(38, m.width-72))
	m.table.SetColumns(m.ipColumns(ipWidth))
}

func (m model) ipColumns(ipWidth int) []table.Column {
	return []table.Column{
		{Title: m.sortColumnTitle(sortIP, "[i]p"), Width: ipWidth},
		{Title: m.sortColumnTitle(sortConnections, "[c]onn"), Width: 8},
		{Title: m.sortColumnTitle(sortInRate, "[r]x/s"), Width: 11},
		{Title: m.sortColumnTitle(sortOutRate, "[o]ut/s"), Width: 11},
		{Title: m.sortColumnTitle(sortTotalIn, "total i[n]"), Width: 14},
		{Title: m.sortColumnTitle(sortTotalOut, "total o[u]t"), Width: 15},
		{Title: m.sortColumnTitle(sortTotal, "[t]otal"), Width: 12},
	}
}

func (m model) sortColumnTitle(field sortField, title string) string {
	if m.sortField != field {
		return title
	}
	if m.sortDesc {
		return title + " v"
	}
	return title + " ^"
}

func (m model) totalRates() (float64, float64) {
	if m.inIPView() {
		stat := m.stats[m.selectedIP]
		if stat == nil {
			return 0, 0
		}
		return stat.InRate, stat.OutRate
	}
	return m.totalInRate, m.totalOutRate
}

func (m model) tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func connCmd() tea.Cmd {
	return tea.Tick(connInterval, func(time.Time) tea.Msg {
		conns, err := listConnections()
		if err != nil {
			return errMsg(err)
		}
		return connMsg(conns)
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
