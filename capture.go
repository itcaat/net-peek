package main

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const defaultSnapLen = 65535

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

type trafficCounters struct {
	InBytes  uint64
	OutBytes uint64
}

type captureMode string

const (
	modeHost    captureMode = "host"
	modeGateway captureMode = "gateway"
)

type captureManager struct {
	errs      chan error
	cancel    context.CancelFunc
	mu        sync.Mutex
	pending   map[string]trafficCounters
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
		errs:      make(chan error, max(1, len(selected)*2)),
		cancel:    cancel,
		pending:   map[string]trafficCounters{},
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
			m.addPacketEvents(m.packetToEvents(packet))
		}
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
	}
}

func (m *captureManager) drainDeltas() map[string]trafficCounters {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pending) == 0 {
		return nil
	}
	deltas := m.pending
	m.pending = map[string]trafficCounters{}
	return deltas
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
