package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	defaultSnapLen = 65535
	connInterval   = 2 * time.Second
)

var refreshIntervals = []time.Duration{
	time.Second,
	3 * time.Second,
	5 * time.Second,
	10 * time.Second,
}

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type direction uint8

const (
	dirIn direction = iota
	dirOut
)

type packetEvent struct {
	remoteIP string
	dir      direction
	bytes    uint64
}

type captureMode string

const (
	modeHost    captureMode = "host"
	modeGateway captureMode = "gateway"
)

type ipStats struct {
	IP           string
	InBytes      uint64
	OutBytes     uint64
	LastInBytes  uint64
	LastOutBytes uint64
	InRate       float64
	OutRate      float64
	Connections  []connection
}

func (s ipStats) Total() uint64 {
	return s.InBytes + s.OutBytes
}

func (s ipStats) TotalRate() float64 {
	return s.InRate + s.OutRate
}

type connection struct {
	Proto  string
	Local  string
	Remote string
	State  string
	PID    string
}

type captureManager struct {
	events    chan packetEvent
	errs      chan error
	cancel    context.CancelFunc
	localNets []*net.IPNet
	localIPs  map[string]struct{}
	mode      captureMode
}

func newCaptureManager(ctx context.Context, iface string) (*captureManager, error) {
	return newCaptureManagerWithMode(ctx, iface, modeHost)
}

func newCaptureManagerWithMode(ctx context.Context, iface string, mode captureMode) (*captureManager, error) {
	ctx, cancel := context.WithCancel(ctx)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		cancel()
		return nil, err
	}

	selected, err := selectCaptureDevicesForMode(devices, iface, mode)
	if err != nil {
		cancel()
		return nil, err
	}
	localIPDevices := selected
	if mode == modeGateway {
		localIPDevices = devices
	}

	manager := &captureManager{
		events:    make(chan packetEvent, 8192),
		errs:      make(chan error, max(1, len(selected)*2)),
		cancel:    cancel,
		localNets: collectLocalNets(selected),
		localIPs:  collectLocalIPs(localIPDevices),
		mode:      mode,
	}

	for _, dev := range selected {
		dev := dev
		go manager.captureInterface(ctx, dev.Name)
	}

	return manager, nil
}

func selectCaptureDevicesForMode(devices []pcap.Interface, iface string, mode captureMode) ([]pcap.Interface, error) {
	if mode == modeGateway && runtime.GOOS == "linux" && (iface == "" || iface == "all") {
		if selected, err := selectCaptureDevices(devices, "any"); err == nil {
			return selected, nil
		}
	}
	return selectCaptureDevices(devices, iface)
}

func selectCaptureDevices(devices []pcap.Interface, iface string) ([]pcap.Interface, error) {
	selected := devices
	if iface != "all" && iface != "" {
		selected = nil
		for _, dev := range devices {
			if dev.Name == iface {
				selected = append(selected, dev)
				break
			}
		}
		if len(selected) == 0 {
			return nil, fmt.Errorf("interface %q not found", iface)
		}
	}
	return selected, nil
}

func (m *captureManager) stop() {
	m.cancel()
}

func (m *captureManager) captureInterface(ctx context.Context, name string) {
	handle, err := pcap.OpenLive(name, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		m.errs <- fmt.Errorf("%s: %w", name, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("ip or ip6"); err != nil {
		m.errs <- fmt.Errorf("%s: set BPF filter: %w", name, err)
		return
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			for _, ev := range m.packetToEvents(packet) {
				select {
				case m.events <- ev:
				default:
				}
			}
		}
	}
}

func (m *captureManager) packetToEvents(packet gopacket.Packet) []packetEvent {
	length := uint64(len(packet.Data()))
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		return m.ipPairToEvents(ipv4.SrcIP, ipv4.DstIP, length)
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		return m.ipPairToEvents(ipv6.SrcIP, ipv6.DstIP, length)
	}
	return nil
}

func (m *captureManager) ipPairToEvents(src, dst net.IP, bytes uint64) []packetEvent {
	if m.mode == modeGateway {
		return m.gatewayIPPairToEvents(src, dst, bytes)
	}

	srcLocal := containsIP(m.localNets, src)
	dstLocal := containsIP(m.localNets, dst)

	switch {
	case srcLocal && !dstLocal:
		return []packetEvent{{remoteIP: dst.String(), dir: dirOut, bytes: bytes}}
	case dstLocal && !srcLocal:
		return []packetEvent{{remoteIP: src.String(), dir: dirIn, bytes: bytes}}
	case srcLocal && dstLocal:
		return []packetEvent{{remoteIP: dst.String(), dir: dirOut, bytes: bytes}}
	default:
		return nil
	}
}

func (m *captureManager) gatewayIPPairToEvents(src, dst net.IP, bytes uint64) []packetEvent {
	events := make([]packetEvent, 0, 2)
	if !isLocalish(src.String()) && m.gatewayIPAllowed(src) {
		events = append(events, packetEvent{remoteIP: src.String(), dir: dirOut, bytes: bytes})
	}
	if !isLocalish(dst.String()) && m.gatewayIPAllowed(dst) {
		events = append(events, packetEvent{remoteIP: dst.String(), dir: dirIn, bytes: bytes})
	}
	return events
}

func (m *captureManager) gatewayIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	_, local := m.localIPs[ip.String()]
	return !local
}

func collectLocalNets(devices []pcap.Interface) []*net.IPNet {
	var nets []*net.IPNet
	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			ip := addr.IP
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			mask := addr.Netmask
			if len(mask) == 0 {
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
			}
			nets = append(nets, &net.IPNet{IP: ip.Mask(mask), Mask: mask})
		}
	}
	return nets
}

func collectLocalIPs(devices []pcap.Interface) map[string]struct{} {
	ips := map[string]struct{}{}
	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			if addr.IP == nil || addr.IP.IsUnspecified() {
				continue
			}
			ips[addr.IP.String()] = struct{}{}
		}
	}
	return ips
}

func containsIP(nets []*net.IPNet, ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

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
	capture     *captureManager
	iface       string
	mode        captureMode
	stats       map[string]*ipStats
	connections map[string][]connection
	table       table.Model
	selectedIP  string
	sortField   sortField
	sortDesc    bool
	paused      bool
	refreshIdx  int
	searching   bool
	searchQuery string
	ifacePicker bool
	ifaceList   []string
	ifaceIndex  int
	errs        []string
	width       int
	height      int
	lastTick    time.Time
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
			m.fasterRefresh()
		case "-", "_":
			m.slowerRefresh()
		case "tab":
			m.openIfacePicker()
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
	nextMode := m.mode
	nextCapture, err := newCaptureManagerWithMode(context.Background(), nextIface, nextMode)
	if err != nil {
		m.errs = append(m.errs, err.Error())
		if len(m.errs) > 4 {
			m.errs = m.errs[len(m.errs)-4:]
		}
		return
	}
	m.capture.stop()
	m.capture = nextCapture
	m.iface = nextIface
	m.ifacePicker = false
	m.selectedIP = ""
	m.searching = false
	m.searchQuery = ""
	m.stats = map[string]*ipStats{}
	m.connections = map[string][]connection{}
	m.lastTick = time.Now()
	m.table.SetRows(nil)
	m.resizeColumns()
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

func (m *model) fasterRefresh() {
	if m.refreshIdx > 0 {
		m.refreshIdx--
	}
}

func (m *model) slowerRefresh() {
	if m.refreshIdx < len(refreshIntervals)-1 {
		m.refreshIdx++
	}
}

func (m model) refreshInterval() time.Duration {
	if m.refreshIdx < 0 || m.refreshIdx >= len(refreshIntervals) {
		return refreshIntervals[0]
	}
	return refreshIntervals[m.refreshIdx]
}

func (m *model) drainEvents() {
	for {
		select {
		case ev := <-m.capture.events:
			stat := m.stats[ev.remoteIP]
			if stat == nil {
				stat = &ipStats{IP: ev.remoteIP}
				m.stats[ev.remoteIP] = stat
			}
			if ev.dir == dirIn {
				stat.InBytes += ev.bytes
			} else {
				stat.OutBytes += ev.bytes
			}
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
	elapsed := now.Sub(m.lastTick).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}
	for _, stat := range m.stats {
		stat.InRate = float64(stat.InBytes-stat.LastInBytes) / elapsed
		stat.OutRate = float64(stat.OutBytes-stat.LastOutBytes) / elapsed
		stat.LastInBytes = stat.InBytes
		stat.LastOutBytes = stat.OutBytes
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
	var inRate, outRate float64
	for _, stat := range m.stats {
		if m.searchQuery != "" && !strings.Contains(stat.IP, m.searchQuery) {
			continue
		}
		inRate += stat.InRate
		outRate += stat.OutRate
	}
	return inRate, outRate
}

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
		mutedStyle.Render("refresh") + " " + valueStyle.Render(m.refreshInterval().String()),
		mutedStyle.Render("rate") + " " + valueStyle.Render("in "+humanMbitRate(totalInRate)+" out "+humanMbitRate(totalOutRate)),
		mutedStyle.Render("sorted") + " " + valueStyle.Render(m.sortField.String()+" "+direction),
	}, "  ")
	if m.mode == modeGateway {
		parts := []string{
			titleStyle.Render("net-peek"),
			mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
			mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
			mutedStyle.Render("state") + " " + valueStyle.Render(state),
			mutedStyle.Render("refresh") + " " + valueStyle.Render(m.refreshInterval().String()),
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
		hotkey(keyStyle, "tab", "iface"),
		hotkey(keyStyle, "/", "search"),
		hotkey(keyStyle, "space", "pause"),
		hotkey(keyStyle, "+/-", "refresh"),
		hotkey(keyStyle, "q", "quit"),
	}, "  ")
	if m.searching {
		keys = strings.Join([]string{
			hotkey(keyStyle, "enter", "open"),
			hotkey(keyStyle, "esc", "clear"),
			hotkey(keyStyle, "backspace", "delete"),
			hotkey(keyStyle, "tab", "iface"),
			hotkey(keyStyle, "space", "pause"),
			hotkey(keyStyle, "+/-", "refresh"),
			hotkey(keyStyle, "ctrl+c", "quit"),
		}, "  ")
	}
	if m.inIPView() {
		primary = strings.Join([]string{
			titleStyle.Render("net-peek"),
			mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
			mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
			mutedStyle.Render("state") + " " + valueStyle.Render(state),
			mutedStyle.Render("refresh") + " " + valueStyle.Render(m.refreshInterval().String()),
			mutedStyle.Render("rate") + " " + valueStyle.Render("in "+humanMbitRate(totalInRate)+" out "+humanMbitRate(totalOutRate)),
			mutedStyle.Render("ip") + " " + valueStyle.Render(m.selectedIP),
		}, "  ")
		if m.mode == modeGateway {
			parts := []string{
				titleStyle.Render("net-peek"),
				mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
				mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
				mutedStyle.Render("state") + " " + valueStyle.Render(state),
				mutedStyle.Render("refresh") + " " + valueStyle.Render(m.refreshInterval().String()),
				mutedStyle.Render("rate") + " " + valueStyle.Render("in "+humanMbitRate(totalInRate)+" out "+humanMbitRate(totalOutRate)),
				mutedStyle.Render("ip") + " " + valueStyle.Render(m.selectedIP),
			}
			primary = strings.Join(parts, "  ")
		}
		keys = strings.Join([]string{
			hotkey(keyStyle, "backspace", "back"),
			hotkey(keyStyle, "esc", "back"),
			hotkey(keyStyle, "tab", "iface"),
			hotkey(keyStyle, "space", "pause"),
			hotkey(keyStyle, "+/-", "refresh"),
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
		status = mutedStyle.Render("gateway mode counts every captured packet by source IP as Out and destination IP as In")
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

func (m model) tickCmd() tea.Cmd {
	return tea.Tick(m.refreshInterval(), func(t time.Time) tea.Msg {
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

func listConnections() (map[string][]connection, error) {
	var conns []connection
	var err error
	if runtime.GOOS == "linux" {
		conns, err = listConnectionsProc()
		if err == nil {
			return groupConnections(conns), nil
		}
	}
	if runtime.GOOS == "darwin" {
		conns, err = listConnectionsLSOF()
		if err == nil {
			return groupConnections(conns), nil
		}
	}
	conns, err = listConnectionsNetstat()
	if err != nil {
		return nil, err
	}
	return groupConnections(conns), nil
}

func listConnectionsProc() ([]connection, error) {
	conns, err := parseProcNetTCPFile("/proc/net/tcp", false)
	if err != nil {
		return nil, err
	}
	conns6, err := parseProcNetTCPFile("/proc/net/tcp6", true)
	if err != nil {
		return nil, err
	}
	conns = append(conns, conns6...)
	return conns, nil
}

func parseProcNetTCPFile(path string, ipv6 bool) ([]connection, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var conns []connection
	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		conn, ok := parseProcNetTCPLine(scanner.Text(), ipv6)
		if ok {
			conns = append(conns, conn)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return conns, nil
}

func parseProcNetTCPLine(line string, ipv6 bool) (connection, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return connection{}, false
	}
	if fields[3] != "01" {
		return connection{}, false
	}
	local, ok := parseProcNetAddr(fields[1], ipv6)
	if !ok {
		return connection{}, false
	}
	remote, ok := parseProcNetAddr(fields[2], ipv6)
	if !ok {
		return connection{}, false
	}
	proto := "tcp"
	if ipv6 {
		proto = "tcp6"
	}
	return connection{Proto: proto, State: "ESTABLISHED", Local: local, Remote: remote}, true
}

func parseProcNetAddr(addr string, ipv6 bool) (string, bool) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return "", false
	}
	hostHex := parts[0]
	portHex := parts[1]

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", false
	}

	var ip net.IP
	if ipv6 {
		ip = parseProcNetIPv6(hostHex)
	} else {
		ip = parseProcNetIPv4(hostHex)
	}
	if ip == nil {
		return "", false
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)), true
}

func parseProcNetIPv4(hostHex string) net.IP {
	raw, err := hex.DecodeString(hostHex)
	if err != nil || len(raw) != net.IPv4len {
		return nil
	}
	return net.IPv4(raw[3], raw[2], raw[1], raw[0])
}

func parseProcNetIPv6(hostHex string) net.IP {
	raw, err := hex.DecodeString(hostHex)
	if err != nil || len(raw) != net.IPv6len {
		return nil
	}
	ip := make(net.IP, net.IPv6len)
	for i := 0; i < net.IPv6len; i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return ip
}

func listConnectionsLSOF() ([]connection, error) {
	cmd := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseLSOFConnections(string(out)), nil
}

func parseLSOFConnections(output string) []connection {
	var conns []connection
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 || fields[0] == "COMMAND" {
			continue
		}
		local, remote, ok := parseLSOFName(strings.Join(fields[8:], " "))
		if !ok {
			continue
		}
		pid := fields[0] + "(" + fields[1] + ")"
		conns = append(conns, connection{Proto: "tcp", State: "ESTABLISHED", Local: local, Remote: remote, PID: pid})
	}
	return conns
}

func parseLSOFName(name string) (string, string, bool) {
	name = strings.TrimSpace(name)
	if idx := strings.Index(name, " ("); idx > -1 {
		name = name[:idx]
	}
	parts := strings.Split(name, "->")
	if len(parts) != 2 {
		return "", "", false
	}
	local := strings.TrimSpace(parts[0])
	remote := strings.TrimSpace(parts[1])
	if local == "" || remote == "" {
		return "", "", false
	}
	return local, remote, true
}

func listConnectionsNetstat() ([]connection, error) {
	cmd := exec.Command("netstat", "-an")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var conns []connection
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := fields[0]
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}
		state := fields[len(fields)-1]
		if strings.HasPrefix(proto, "tcp") && state != "ESTABLISHED" {
			continue
		}
		local := fields[3]
		remote := fields[4]
		conns = append(conns, connection{Proto: proto, State: state, Local: local, Remote: remote})
	}
	return conns, nil
}

func groupConnections(conns []connection) map[string][]connection {
	grouped := make(map[string][]connection)
	for _, c := range conns {
		ip := remoteIPFromAddr(c.Remote)
		if ip == "" || isLocalish(ip) {
			continue
		}
		grouped[ip] = append(grouped[ip], c)
	}
	return grouped
}

var bracketAddr = regexp.MustCompile(`^\[(.*)\]:(\d+|\*)$`)

func remoteIPFromAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "tcp:")
	addr = strings.TrimPrefix(addr, "udp:")
	if addr == "" || addr == "*:*" || addr == "*.*" {
		return ""
	}
	if match := bracketAddr.FindStringSubmatch(addr); len(match) == 3 {
		return normalizeIP(match[1])
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return normalizeIP(host)
	}
	if idx := strings.LastIndex(addr, "."); idx > -1 {
		candidate := addr[:idx]
		if ip := normalizeIP(candidate); ip != "" {
			return ip
		}
	}
	if idx := strings.LastIndex(addr, ":"); idx > -1 {
		candidate := addr[:idx]
		if ip := normalizeIP(candidate); ip != "" {
			return ip
		}
	}
	return normalizeIP(addr)
}

func normalizeIP(ip string) string {
	ip = strings.Trim(ip, "[]")
	if idx := strings.LastIndex(ip, "%"); idx > -1 {
		ip = ip[:idx]
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func isLocalish(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	return parsed.IsLoopback() || parsed.IsUnspecified() || parsed.IsMulticast()
}

func humanBytes(v float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	for i := 0; i < len(units)-1 && v >= 1024; i++ {
		v /= 1024
		if v < 1024 {
			return fmt.Sprintf("%.1f%s", v, units[i+1])
		}
	}
	return fmt.Sprintf("%.0f%s", v, units[0])
}

func humanMbitRate(bytesPerSecond float64) string {
	return fmt.Sprintf("%.2fMbit/s", bytesPerSecond*8/1000/1000)
}

func humanBitRate(bytesPerSecond float64) string {
	bits := bytesPerSecond * 8
	units := []string{"bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"}
	for i := 0; i < len(units)-1 && bits >= 1000; i++ {
		bits /= 1000
		if bits < 1000 {
			return fmt.Sprintf("%.1f%s", bits, units[i+1])
		}
	}
	return fmt.Sprintf("%.0f%s", bits, units[0])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func availableInterfaces() (string, error) {
	names, err := availableInterfaceNames()
	if err != nil {
		return "", err
	}
	return strings.Join(names, ", "), nil
}

func availableInterfaceNames() ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(devices)+1)
	names = append(names, "all")
	for _, dev := range devices {
		names = append(names, dev.Name)
	}
	if len(names) > 1 {
		sort.Strings(names[1:])
	}
	return names, nil
}

func main() {
	iface := flag.String("i", "all", "network interface to capture, or all")
	modeFlag := flag.String("mode", string(modeHost), "capture mode: host or gateway")
	list := flag.Bool("list", false, "list capture interfaces")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("net-peek %s (%s, %s)\n", version, commit, date)
		return
	}

	if *list {
		names, err := availableInterfaces()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(names)
		return
	}

	mode := captureMode(*modeFlag)
	switch mode {
	case modeHost:
	case modeGateway:
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q; expected host or gateway\n", *modeFlag)
		os.Exit(1)
	}

	capture, err := newCaptureManagerWithMode(context.Background(), *iface, mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer capture.stop()

	p := tea.NewProgram(newModel(capture, *iface, mode), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
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
