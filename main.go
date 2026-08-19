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
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	connInterval = 2 * time.Second
)

var avgWindows = []time.Duration{
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

var clientCandidateNets = []*net.IPNet{
	mustParseCIDR("100.64.0.0/10"),
	mustParseCIDR("fc00::/7"),
}

type direction uint8

const (
	dirIn direction = iota
	dirOut
)

type packetEvent struct {
	remoteIP string
	peerIP   string
	proto    string
	flowID   string
	dir      direction
	bytes    uint64
}

type trafficCounters struct {
	InBytes  uint64
	OutBytes uint64
}

type trafficDeltas struct {
	IPs   map[string]trafficCounters
	Flows map[string]flowDelta
}

type flowDelta struct {
	ClientIP string
	RemoteIP string
	Proto    string
	InBytes  uint64
	OutBytes uint64
}

type gatewayFlowOwner struct {
	ClientIP   string
	RemoteIP   string
	ClientPort string
	RemotePort string
	Proto      string
}

type captureMode string

const (
	modeHost    captureMode = "host"
	modeGateway captureMode = "gateway"
)

type ipStats struct {
	IP          string
	InBytes     uint64
	OutBytes    uint64
	InRate      float64
	OutRate     float64
	FlowCount   int
	Connections []connection
	History     []statSample
}

type statSample struct {
	At       time.Time
	InBytes  uint64
	OutBytes uint64
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

type flowStats struct {
	ClientIP string
	RemoteIP string
	Proto    string
	InBytes  uint64
	OutBytes uint64
	InRate   float64
	OutRate  float64
	LastSeen time.Time
	History  []statSample
}

func (s flowStats) Total() uint64 {
	return s.InBytes + s.OutBytes
}

func (s flowStats) TotalRate() float64 {
	return s.InRate + s.OutRate
}

func activeFlowWindow() time.Duration {
	return 30 * time.Second
}

type captureManager struct {
	errs             chan error
	cancel           context.CancelFunc
	mu               sync.Mutex
	pending          map[string]trafficCounters
	flows            map[string]flowDelta
	owners           map[string]gatewayFlowOwner
	localNets        []*net.IPNet
	ifaceNets        map[int][]*net.IPNet
	localIPs         map[string]struct{}
	mode             captureMode
	closeFn          func()
	readKernelDeltas func(*captureManager)
}

func newCaptureManager(ctx context.Context, iface string) (*captureManager, error) {
	return newCaptureManagerWithMode(ctx, iface, modeHost)
}

func newCaptureManagerWithMode(ctx context.Context, iface string, mode captureMode) (*captureManager, error) {
	ctx, cancel := context.WithCancel(ctx)
	ifaces, err := selectNetworkInterfaces(iface)
	if err != nil {
		cancel()
		return nil, err
	}
	allIfaces := ifaces
	if mode == modeGateway {
		allIfaces, err = usableNetworkInterfaces()
		if err != nil {
			cancel()
			return nil, err
		}
	}

	manager := &captureManager{
		errs:      make(chan error, max(1, len(ifaces)*2)),
		cancel:    cancel,
		pending:   map[string]trafficCounters{},
		flows:     map[string]flowDelta{},
		owners:    map[string]gatewayFlowOwner{},
		localNets: collectLocalNets(ifaces),
		ifaceNets: collectInterfaceNets(ifaces),
		localIPs:  collectLocalIPs(allIfaces),
		mode:      mode,
	}

	if err := newPlatformCapture(ctx, manager, ifaces); err != nil {
		cancel()
		return nil, err
	}

	return manager, nil
}

func selectNetworkInterfaces(iface string) ([]net.Interface, error) {
	if iface == "" || iface == "all" {
		return usableNetworkInterfaces()
	}
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found", iface)
	}
	if !isUsableInterface(dev) {
		return nil, fmt.Errorf("interface %q is not up or is loopback", iface)
	}
	return []net.Interface{*dev}, nil
}

func usableNetworkInterfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	selected := make([]net.Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		if isUsableInterface(&iface) {
			selected = append(selected, iface)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no usable network interfaces found")
	}
	return selected, nil
}

func isUsableInterface(iface *net.Interface) bool {
	return iface != nil && iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0
}

func (m *captureManager) stop() {
	m.cancel()
	if m.closeFn != nil {
		m.closeFn()
	}
}

func (m *captureManager) addPacketEvents(events []packetEvent) {
	if len(events) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ev := range events {
		counters := m.pending[ev.remoteIP]
		if ev.dir == dirIn {
			counters.InBytes += ev.bytes
		} else {
			counters.OutBytes += ev.bytes
		}
		m.pending[ev.remoteIP] = counters
		if ev.flowID != "" {
			flow := m.flows[ev.flowID]
			if flow.ClientIP == "" {
				flow.ClientIP = ev.remoteIP
				flow.RemoteIP = ev.peerIP
				flow.Proto = ev.proto
			}
			if ev.dir == dirIn {
				flow.InBytes += ev.bytes
			} else {
				flow.OutBytes += ev.bytes
			}
			m.flows[ev.flowID] = flow
		}
	}
}

func (m *captureManager) drainDeltas() trafficDeltas {
	if m.readKernelDeltas != nil {
		m.readKernelDeltas(m)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pending) == 0 && len(m.flows) == 0 {
		return trafficDeltas{}
	}
	deltas := trafficDeltas{IPs: m.pending, Flows: m.flows}
	m.pending = map[string]trafficCounters{}
	m.flows = map[string]flowDelta{}
	return deltas
}

type flowMeta struct {
	Proto   string
	SrcPort string
	DstPort string
}

func (m *captureManager) ipPairToEvents(src, dst net.IP, meta flowMeta, bytes uint64) []packetEvent {
	if m.mode == modeGateway {
		return m.gatewayIPPairToEvents(src, dst, meta, bytes)
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

func (m *captureManager) gatewayIPPairToEvents(src, dst net.IP, meta flowMeta, bytes uint64) []packetEvent {
	srcClient := m.gatewayClientAllowed(src)
	dstClient := m.gatewayClientAllowed(dst)
	if !srcClient && !dstClient {
		return nil
	}

	srcIP := src.String()
	dstIP := dst.String()
	owner := gatewayFlowOwner{}
	switch {
	case srcClient && !dstClient:
		owner = gatewayFlowOwner{ClientIP: srcIP, RemoteIP: dstIP, ClientPort: meta.SrcPort, RemotePort: meta.DstPort, Proto: meta.Proto}
	case dstClient && !srcClient:
		owner = gatewayFlowOwner{ClientIP: dstIP, RemoteIP: srcIP, ClientPort: meta.DstPort, RemotePort: meta.SrcPort, Proto: meta.Proto}
	default:
		owner = m.gatewayPrivateFlowOwner(srcIP, dstIP, meta)
	}
	if owner.ClientIP == "" {
		return nil
	}

	dir := dirIn
	if srcIP == owner.ClientIP && meta.SrcPort == owner.ClientPort {
		dir = dirOut
	} else if meta.SrcPort == "" && srcIP == owner.ClientIP {
		dir = dirOut
	}

	return []packetEvent{{
		remoteIP: owner.ClientIP,
		peerIP:   owner.RemoteIP,
		proto:    owner.Proto,
		flowID:   gatewayFlowID(owner.ClientIP, owner.RemoteIP, owner.Proto, owner.ClientPort, owner.RemotePort),
		dir:      dir,
		bytes:    bytes,
	}}
}

func (m *captureManager) gatewayPrivateFlowOwner(srcIP, dstIP string, meta flowMeta) gatewayFlowOwner {
	key := canonicalGatewayFlowKey(srcIP, dstIP, meta)
	m.mu.Lock()
	defer m.mu.Unlock()
	if owner, ok := m.owners[key]; ok {
		return owner
	}
	owner := gatewayFlowOwner{
		ClientIP:   srcIP,
		RemoteIP:   dstIP,
		ClientPort: meta.SrcPort,
		RemotePort: meta.DstPort,
		Proto:      meta.Proto,
	}
	m.owners[key] = owner
	return owner
}

func (m *captureManager) gatewayClientAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	_, local := m.localIPs[ip.String()]
	return !local && isClientCandidateIP(ip)
}

func gatewayFlowID(clientIP, remoteIP, proto, clientPort, remotePort string) string {
	return strings.Join([]string{clientIP, clientPort, remoteIP, remotePort, proto}, "|")
}

func canonicalGatewayFlowKey(srcIP, dstIP string, meta flowMeta) string {
	left := srcIP + ":" + meta.SrcPort
	right := dstIP + ":" + meta.DstPort
	if left > right {
		left, right = right, left
	}
	return strings.Join([]string{left, right, meta.Proto}, "|")
}

func collectLocalNets(ifaces []net.Interface) []*net.IPNet {
	var nets []*net.IPNet
	for _, iface := range ifaces {
		nets = append(nets, interfaceNets(iface)...)
	}
	return nets
}

func collectInterfaceNets(ifaces []net.Interface) map[int][]*net.IPNet {
	nets := map[int][]*net.IPNet{}
	for _, iface := range ifaces {
		nets[iface.Index] = interfaceNets(iface)
	}
	return nets
}

func interfaceNets(iface net.Interface) []*net.IPNet {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	nets := make([]*net.IPNet, 0, len(addrs))
	for _, addr := range addrs {
		ip, n, ok := addrToIPNet(addr)
		if !ok {
			continue
		}
		nets = append(nets, &net.IPNet{IP: ip.Mask(n.Mask), Mask: n.Mask})
	}
	return nets
}

func collectLocalIPs(ifaces []net.Interface) map[string]struct{} {
	ips := map[string]struct{}{}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, ok := addrToIPNet(addr)
			if ok {
				ips[ip.String()] = struct{}{}
			}
		}
	}
	return ips
}

func addrToIPNet(addr net.Addr) (net.IP, *net.IPNet, bool) {
	ipNet, ok := addr.(*net.IPNet)
	if !ok || ipNet.IP == nil || ipNet.IP.IsUnspecified() {
		return nil, nil, false
	}
	return ipNet.IP, ipNet, true
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

func isClientCandidateIP(ip net.IP) bool {
	if ip == nil || isLocalish(ip.String()) {
		return false
	}
	if ip.IsPrivate() {
		return true
	}
	if containsIP(clientCandidateNets, ip) {
		return true
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
	capture       *captureManager
	iface         string
	mode          captureMode
	stats         map[string]*ipStats
	flows         map[string]*flowStats
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
		flows:       map[string]*flowStats{},
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
	m.flows = map[string]*flowStats{}
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
	now := time.Now()
	deltas := m.capture.drainDeltas()
	for ip, delta := range deltas.IPs {
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
	for id, delta := range deltas.Flows {
		flow := m.flows[id]
		if flow == nil {
			flow = &flowStats{
				ClientIP: delta.ClientIP,
				RemoteIP: delta.RemoteIP,
				Proto:    delta.Proto,
			}
			m.flows[id] = flow
		}
		flow.InBytes += delta.InBytes
		flow.OutBytes += delta.OutBytes
		flow.LastSeen = now
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
		stat.FlowCount = 0
	}
	for _, flow := range m.flows {
		flow.History = append(flow.History, statSample{At: now, InBytes: flow.InBytes, OutBytes: flow.OutBytes})
		flow.History = trimStatHistory(flow.History, now)
		flow.InRate, flow.OutRate = ratesForHistory(flow.History, now, m.avgWindow())
		if now.Sub(flow.LastSeen) <= activeFlowWindow() {
			if stat := m.stats[flow.ClientIP]; stat != nil {
				stat.FlowCount++
			}
		}
	}

	for _, stat := range m.stats {
		stat.History = append(stat.History, statSample{At: now, InBytes: stat.InBytes, OutBytes: stat.OutBytes})
		stat.trimHistory(now)
		stat.InRate, stat.OutRate = stat.ratesForWindow(now, m.avgWindow())
		stat.Connections = m.connections[stat.IP]
	}
	m.lastTick = now
}

func (s *ipStats) trimHistory(now time.Time) {
	s.History = trimStatHistory(s.History, now)
}

func trimStatHistory(history []statSample, now time.Time) []statSample {
	maxWindow := avgWindows[len(avgWindows)-1] + time.Second
	keepFrom := 0
	for keepFrom < len(history) && now.Sub(history[keepFrom].At) > maxWindow {
		keepFrom++
	}
	if keepFrom > 0 {
		return append([]statSample(nil), history[keepFrom:]...)
	}
	return history
}

func (s *ipStats) ratesForWindow(now time.Time, window time.Duration) (float64, float64) {
	return ratesForHistory(s.History, now, window)
}

func ratesForHistory(history []statSample, now time.Time, window time.Duration) (float64, float64) {
	if len(history) < 2 {
		return 0, 0
	}
	current := history[len(history)-1]
	base := history[0]
	for i := len(history) - 2; i >= 0; i-- {
		if now.Sub(history[i].At) >= window {
			base = history[i]
			break
		}
		base = history[i]
	}
	elapsed := current.At.Sub(base.At).Seconds()
	if elapsed <= 0 {
		return 0, 0
	}
	return float64(current.InBytes-base.InBytes) / elapsed, float64(current.OutBytes-base.OutBytes) / elapsed
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
		cmp := compareStats(stats[i], stats[j], m.sortField, m.mode)
		if cmp == 0 {
			cmp = compareStats(stats[i], stats[j], sortTotalRate, m.mode)
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
			strconv.Itoa(statConnectionCount(stat, m.mode)),
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
	if m.mode == modeGateway {
		m.refreshGatewayFlowRows()
		return
	}

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

func (m *model) refreshGatewayFlowRows() {
	flows := make([]*flowStats, 0)
	for _, flow := range m.flows {
		if flow.ClientIP == m.selectedIP {
			flows = append(flows, flow)
		}
	}
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].TotalRate() == flows[j].TotalRate() {
			if flows[i].RemoteIP == flows[j].RemoteIP {
				return flows[i].Proto < flows[j].Proto
			}
			return flows[i].RemoteIP < flows[j].RemoteIP
		}
		return flows[i].TotalRate() > flows[j].TotalRate()
	})

	rows := make([]table.Row, 0, len(flows))
	for _, flow := range flows {
		rows = append(rows, table.Row{
			flow.RemoteIP,
			flow.Proto,
			humanBitRate(flow.InRate),
			humanBitRate(flow.OutRate),
			humanBytes(float64(flow.InBytes)),
			humanBytes(float64(flow.OutBytes)),
			humanBytes(float64(flow.Total())),
		})
	}
	m.table.SetRows(rows)
}

func compareStats(a, b *ipStats, field sortField, mode captureMode) int {
	switch field {
	case sortIP:
		return strings.Compare(a.IP, b.IP)
	case sortConnections:
		return compareInt(statConnectionCount(a, mode), statConnectionCount(b, mode))
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

func statConnectionCount(stat *ipStats, mode captureMode) int {
	if mode == modeGateway {
		return stat.FlowCount
	}
	return len(stat.Connections)
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
		if m.mode == modeGateway {
			remoteWidth := max(18, min(42, m.width-72))
			m.table.SetColumns([]table.Column{
				{Title: "Destination", Width: remoteWidth},
				{Title: "Proto", Width: 7},
				{Title: "Down/s", Width: 11},
				{Title: "Up/s", Width: 11},
				{Title: "Total Down", Width: 13},
				{Title: "Total Up", Width: 12},
				{Title: "Total", Width: 12},
			})
			return
		}
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
	if m.mode == modeGateway {
		return []table.Column{
			{Title: m.sortColumnTitle(sortIP, "client [i]p"), Width: ipWidth},
			{Title: m.sortColumnTitle(sortConnections, "[c]onn"), Width: 8},
			{Title: m.sortColumnTitle(sortInRate, "down/[r]"), Width: 11},
			{Title: m.sortColumnTitle(sortOutRate, "up/[o]"), Width: 11},
			{Title: m.sortColumnTitle(sortTotalIn, "total dow[n]"), Width: 14},
			{Title: m.sortColumnTitle(sortTotalOut, "total [u]p"), Width: 15},
			{Title: m.sortColumnTitle(sortTotal, "[t]otal"), Width: 12},
		}
	}
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
	rateText := "in " + humanMbitRate(totalInRate) + " out " + humanMbitRate(totalOutRate)
	if m.mode == modeGateway {
		rateText = "down " + humanMbitRate(totalInRate) + " up " + humanMbitRate(totalOutRate)
	}
	primary := strings.Join([]string{
		titleStyle.Render("net-peek"),
		mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
		mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
		mutedStyle.Render("state") + " " + valueStyle.Render(state),
		mutedStyle.Render("avg") + " " + valueStyle.Render(m.avgWindow().String()),
		mutedStyle.Render("rate") + " " + valueStyle.Render(rateText),
		mutedStyle.Render("sorted") + " " + valueStyle.Render(m.sortField.String()+" "+direction),
	}, "  ")
	if m.mode == modeGateway {
		parts := []string{
			titleStyle.Render("net-peek"),
			mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
			mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
			mutedStyle.Render("state") + " " + valueStyle.Render(state),
			mutedStyle.Render("avg") + " " + valueStyle.Render(m.avgWindow().String()),
			mutedStyle.Render("rate") + " " + valueStyle.Render(rateText),
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
			mutedStyle.Render("rate") + " " + valueStyle.Render(rateText),
			mutedStyle.Render("ip") + " " + valueStyle.Render(m.selectedIP),
		}, "  ")
		if m.mode == modeGateway {
			parts := []string{
				titleStyle.Render("net-peek"),
				mutedStyle.Render("mode") + " " + valueStyle.Render(string(m.mode)),
				mutedStyle.Render("iface") + " " + valueStyle.Render(m.iface),
				mutedStyle.Render("state") + " " + valueStyle.Render(state),
				mutedStyle.Render("avg") + " " + valueStyle.Render(m.avgWindow().String()),
				mutedStyle.Render("rate") + " " + valueStyle.Render(rateText),
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
		status = mutedStyle.Render("gateway mode shows private/CGNAT/ULA client candidates; enter opens destinations")
	}
	if m.inIPView() {
		stat := m.stats[m.selectedIP]
		if stat != nil {
			if m.mode == modeGateway {
				status = mutedStyle.Render("flows: " + strconv.Itoa(stat.FlowCount) + " | down: " + humanBytes(float64(stat.InBytes)) + " | up: " + humanBytes(float64(stat.OutBytes)) + " | rate: " + humanBitRate(stat.TotalRate()))
			} else {
				status = mutedStyle.Render("connections: " + strconv.Itoa(len(m.connections[m.selectedIP])) + " | in: " + humanBytes(float64(stat.InBytes)) + " | out: " + humanBytes(float64(stat.OutBytes)) + " | rate: " + humanBitRate(stat.TotalRate()))
			}
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
	if m.inIPView() {
		if m.mode == modeGateway {
			if m.gatewayFlowCount(m.selectedIP) == 0 {
				status += "\n" + mutedStyle.Render("No destinations for this client yet.")
			}
		} else if len(m.connections[m.selectedIP]) == 0 {
			status += "\n" + mutedStyle.Render("No established connections for this IP right now.")
		}
	}

	return boxStyle.Render(header + "\n\n" + body + "\n\n" + status)
}

func (m model) gatewayFlowCount(clientIP string) int {
	count := 0
	for _, flow := range m.flows {
		if flow.ClientIP == clientIP {
			count++
		}
	}
	return count
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

func mustParseCIDR(cidr string) *net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return n
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
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ifaces)+1)
	names = append(names, "all")
	for _, iface := range ifaces {
		if isUsableInterface(&iface) {
			names = append(names, iface.Name)
		}
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
