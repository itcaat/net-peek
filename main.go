package main

import (
	"context"
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
	statInterval   = time.Second
	connInterval   = 2 * time.Second
)

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
}

func newCaptureManager(ctx context.Context, iface string) (*captureManager, error) {
	ctx, cancel := context.WithCancel(ctx)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		cancel()
		return nil, err
	}

	selected := devices
	if iface != "all" {
		selected = nil
		for _, dev := range devices {
			if dev.Name == iface {
				selected = append(selected, dev)
				break
			}
		}
		if len(selected) == 0 {
			cancel()
			return nil, fmt.Errorf("interface %q not found", iface)
		}
	}

	manager := &captureManager{
		events:    make(chan packetEvent, 8192),
		errs:      make(chan error, len(selected)),
		cancel:    cancel,
		localNets: collectLocalNets(selected),
	}

	for _, dev := range selected {
		dev := dev
		go manager.captureInterface(ctx, dev.Name)
	}

	return manager, nil
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
			if ev, ok := m.packetToEvent(packet); ok {
				select {
				case m.events <- ev:
				default:
				}
			}
		}
	}
}

func (m *captureManager) packetToEvent(packet gopacket.Packet) (packetEvent, bool) {
	length := uint64(len(packet.Data()))
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		return m.ipPairToEvent(ipv4.SrcIP, ipv4.DstIP, length)
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		return m.ipPairToEvent(ipv6.SrcIP, ipv6.DstIP, length)
	}
	return packetEvent{}, false
}

func (m *captureManager) ipPairToEvent(src, dst net.IP, bytes uint64) (packetEvent, bool) {
	srcLocal := containsIP(m.localNets, src)
	dstLocal := containsIP(m.localNets, dst)

	switch {
	case srcLocal && !dstLocal:
		return packetEvent{remoteIP: dst.String(), dir: dirOut, bytes: bytes}, true
	case dstLocal && !srcLocal:
		return packetEvent{remoteIP: src.String(), dir: dirIn, bytes: bytes}, true
	case srcLocal && dstLocal:
		return packetEvent{remoteIP: dst.String(), dir: dirOut, bytes: bytes}, true
	default:
		return packetEvent{}, false
	}
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
	stats       map[string]*ipStats
	connections map[string][]connection
	table       table.Model
	selectedIP  string
	sortField   sortField
	sortDesc    bool
	paused      bool
	errs        []string
	width       int
	height      int
	lastTick    time.Time
}

func newModel(capture *captureManager, iface string) model {
	columns := []table.Column{
		{Title: "IP", Width: 28},
		{Title: "Conn", Width: 6},
		{Title: "In/s", Width: 11},
		{Title: "Out/s", Width: 11},
		{Title: "Total In", Width: 12},
		{Title: "Total Out", Width: 12},
		{Title: "Total", Width: 12},
	}
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
		stats:       map[string]*ipStats{},
		connections: map[string][]connection{},
		table:       t,
		sortField:   sortTotalRate,
		sortDesc:    true,
		lastTick:    time.Now(),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), connCmd())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table.SetHeight(max(5, msg.Height-9))
		m.resizeColumns()
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.capture.stop()
			return m, tea.Quit
		case "esc", "backspace", "left":
			if m.inIPView() {
				m.selectedIP = ""
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
		case "1":
			m.setSort(sortIP)
		case "2":
			m.setSort(sortConnections)
		case "3":
			m.setSort(sortInRate)
		case "4":
			m.setSort(sortOutRate)
		case "5":
			m.setSort(sortTotalIn)
		case "6":
			m.setSort(sortTotalOut)
		case "7":
			m.setSort(sortTotal)
		}
	case tickMsg:
		if !m.paused {
			m.drainEvents()
			m.updateRates(time.Time(msg))
			m.refreshRows()
		}
		return m, tickCmd()
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
	m.refreshRows()
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
			humanBytes(stat.InRate) + "/s",
			humanBytes(stat.OutRate) + "/s",
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
	m.table.SetColumns([]table.Column{
		{Title: "IP", Width: ipWidth},
		{Title: "Conn", Width: 6},
		{Title: "In/s", Width: 11},
		{Title: "Out/s", Width: 11},
		{Title: "Total In", Width: 12},
		{Title: "Total Out", Width: 12},
		{Title: "Total", Width: 12},
	})
}

func (m model) View() string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
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
	keys := "enter open | 1 IP 2 Conn 3 In/s 4 Out/s 5 Tin 6 Tout 7 Total | space pause | q quit"
	if m.inIPView() {
		keys = "backspace/esc back | space pause | q quit"
	}
	header := titleStyle.Render("net-peek") + " " + mutedStyle.Render("interface: "+m.iface+" | "+state+" | sort: "+m.sortField.String()+" "+direction+" | "+keys)
	if m.inIPView() {
		header = titleStyle.Render("net-peek") + " " + mutedStyle.Render("interface: "+m.iface+" | "+state+" | IP: "+m.selectedIP+" | "+keys)
	}
	body := m.table.View()

	status := mutedStyle.Render("capturing packets; totals are since start")
	if m.inIPView() {
		stat := m.stats[m.selectedIP]
		if stat != nil {
			status = mutedStyle.Render("connections: " + strconv.Itoa(len(m.connections[m.selectedIP])) + " | in: " + humanBytes(float64(stat.InBytes)) + " | out: " + humanBytes(float64(stat.OutBytes)) + " | rate: " + humanBytes(stat.TotalRate()) + "/s")
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

func tickCmd() tea.Cmd {
	return tea.Tick(statInterval, func(t time.Time) tea.Msg {
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
		conns, err = listConnectionsSS()
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

func listConnectionsSS() ([]connection, error) {
	cmd := exec.Command("ss", "-Htanup")
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
		state := fields[1]
		local := fields[3]
		remote := fields[4]
		pid := ""
		if len(fields) > 5 {
			pid = strings.Join(fields[5:], " ")
		}
		if state != "ESTAB" && state != "ESTABLISHED" {
			continue
		}
		conns = append(conns, connection{Proto: proto, State: state, Local: local, Remote: remote, PID: pid})
	}
	return conns, nil
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
	addr = strings.Trim(addr, "[]")
	if match := bracketAddr.FindStringSubmatch(addr); len(match) == 3 {
		return match[1]
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	if idx := strings.LastIndex(addr, "."); idx > -1 {
		candidate := addr[:idx]
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	return ""
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
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(devices))
	for _, dev := range devices {
		names = append(names, dev.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", "), nil
}

func main() {
	iface := flag.String("i", "all", "network interface to capture, or all")
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

	capture, err := newCaptureManager(context.Background(), *iface)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer capture.stop()

	p := tea.NewProgram(newModel(capture, *iface), tea.WithAltScreen())
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
