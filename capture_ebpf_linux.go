//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	nl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	bpfDirIngress = 0
	bpfDirEgress  = 1
)

func newPlatformCapture(ctx context.Context, manager *captureManager, ifaces []net.Interface) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}

	var attachments []captureAttachment
	cleanup := func() {
		for _, attachment := range attachments {
			_ = attachment.Close()
		}
		_ = objs.Close()
	}

	for _, iface := range ifaces {
		attachment, err := attachInterfacePrograms(iface, objs.IngressAccount, objs.EgressAccount)
		if err != nil {
			cleanup()
			return err
		}
		attachments = append(attachments, attachment)
	}

	snapshots := map[bpfFlowKey]bpfFlowValue{}
	manager.closeFn = cleanup
	manager.readKernelDeltas = func(manager *captureManager) {
		iter := objs.Flows.Iterate()
		var key bpfFlowKey
		var value bpfFlowValue
		for iter.Next(&key, &value) {
			previous := snapshots[key]
			if value.Bytes <= previous.Bytes {
				continue
			}
			snapshots[key] = value
			events := manager.bpfFlowToEvents(key, value.Bytes-previous.Bytes)
			manager.addPacketEvents(events)
		}
		if err := iter.Err(); err != nil {
			select {
			case manager.errs <- fmt.Errorf("read eBPF flows: %w", err):
			default:
			}
		}
	}

	go func() {
		<-ctx.Done()
		cleanup()
	}()

	return nil
}

type captureAttachment interface {
	Close() error
}

type multiAttachment []captureAttachment

func (m multiAttachment) Close() error {
	var errs []error
	for _, attachment := range m {
		if err := attachment.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func attachInterfacePrograms(iface net.Interface, ingressProg, egressProg *ebpf.Program) (captureAttachment, error) {
	tcx, err := attachInterfaceTCX(iface, ingressProg, egressProg)
	if err == nil {
		return tcx, nil
	}

	legacy, legacyErr := attachInterfaceClsact(iface, ingressProg, egressProg)
	if legacyErr == nil {
		return legacy, nil
	}
	return nil, fmt.Errorf("%s: attach eBPF TCX failed: %v; legacy clsact failed: %w", iface.Name, err, legacyErr)
}

func attachInterfaceTCX(iface net.Interface, ingressProg, egressProg *ebpf.Program) (captureAttachment, error) {
	ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   ingressProg,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, err
	}

	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   egressProg,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		_ = ingress.Close()
		return nil, err
	}

	return multiAttachment{ingress, egress}, nil
}

func attachInterfaceClsact(iface net.Interface, ingressProg, egressProg *ebpf.Program) (captureAttachment, error) {
	link, err := nl.LinkByName(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("%s: lookup netlink interface: %w", iface.Name, err)
	}

	qdisc := &nl.Clsact{
		QdiscAttrs: nl.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    nl.MakeHandle(0xffff, 0),
			Parent:    nl.HANDLE_CLSACT,
		},
	}
	if err := nl.QdiscAdd(qdisc); err != nil && !errors.Is(err, syscall.EEXIST) && !os.IsExist(err) {
		return nil, fmt.Errorf("%s: add clsact qdisc: %w", iface.Name, err)
	}

	handleBase := uint16(os.Getpid() & 0xffff)
	if handleBase == 0 {
		handleBase = 1
	}
	ingressFilter := bpfTCFilter(link.Attrs().Index, nl.HANDLE_MIN_INGRESS, nl.MakeHandle(handleBase, 1), "netpeek_ingress", ingressProg)
	if err := nl.FilterAdd(ingressFilter); err != nil {
		return nil, fmt.Errorf("%s: add clsact ingress filter: %w", iface.Name, err)
	}

	egressFilter := bpfTCFilter(link.Attrs().Index, nl.HANDLE_MIN_EGRESS, nl.MakeHandle(handleBase, 2), "netpeek_egress", egressProg)
	if err := nl.FilterAdd(egressFilter); err != nil {
		_ = nl.FilterDel(ingressFilter)
		return nil, fmt.Errorf("%s: add clsact egress filter: %w", iface.Name, err)
	}

	return legacyTCAttachment{filters: []*nl.BpfFilter{ingressFilter, egressFilter}}, nil
}

func bpfTCFilter(linkIndex int, parent, handle uint32, name string, program *ebpf.Program) *nl.BpfFilter {
	return &nl.BpfFilter{
		FilterAttrs: nl.FilterAttrs{
			LinkIndex: linkIndex,
			Parent:    parent,
			Handle:    handle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           program.FD(),
		Name:         name,
		DirectAction: true,
	}
}

type legacyTCAttachment struct {
	filters []*nl.BpfFilter
}

func (a legacyTCAttachment) Close() error {
	var errs []error
	for _, filter := range a.filters {
		if err := nl.FilterDel(filter); err != nil && !errors.Is(err, syscall.ENOENT) && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *captureManager) bpfFlowToEvents(key bpfFlowKey, bytes uint64) []packetEvent {
	src := bpfIP(key.Family, key.Src)
	dst := bpfIP(key.Family, key.Dst)
	if src == nil || dst == nil {
		return nil
	}

	meta := flowMeta{
		Proto:   protoName(key.Proto),
		SrcPort: strconv.Itoa(int(ntohs(key.SrcPort))),
		DstPort: strconv.Itoa(int(ntohs(key.DstPort))),
	}
	if key.SrcPort == 0 {
		meta.SrcPort = ""
	}
	if key.DstPort == 0 {
		meta.DstPort = ""
	}

	if m.mode == modeHost {
		return m.ipPairToEvents(src, dst, meta, bytes)
	}
	return m.gatewayBPFToEvents(key.Ifindex, key.Direction, src, dst, meta, bytes)
}

func (m *captureManager) gatewayBPFToEvents(ifindex uint32, packetDirection uint8, src, dst net.IP, meta flowMeta, bytes uint64) []packetEvent {
	switch packetDirection {
	case bpfDirIngress:
		if !m.gatewayClientOnInterface(int(ifindex), src) {
			return nil
		}
		client := src.String()
		remote := dst.String()
		return []packetEvent{{
			remoteIP: client,
			peerIP:   remote,
			proto:    meta.Proto,
			flowID:   gatewayFlowID(client, remote, meta.Proto, meta.SrcPort, meta.DstPort),
			dir:      dirOut,
			bytes:    bytes,
		}}
	case bpfDirEgress:
		if !m.gatewayClientOnInterface(int(ifindex), dst) {
			return nil
		}
		client := dst.String()
		remote := src.String()
		return []packetEvent{{
			remoteIP: client,
			peerIP:   remote,
			proto:    meta.Proto,
			flowID:   gatewayFlowID(client, remote, meta.Proto, meta.DstPort, meta.SrcPort),
			dir:      dirIn,
			bytes:    bytes,
		}}
	default:
		return nil
	}
}

func (m *captureManager) gatewayClientOnInterface(ifindex int, ip net.IP) bool {
	return m.gatewayClientAllowed(ip) && containsIP(m.ifaceNets[ifindex], ip)
}

func bpfIP(family uint8, raw [16]uint8) net.IP {
	switch family {
	case 4:
		return net.IPv4(raw[0], raw[1], raw[2], raw[3])
	case 6:
		ip := make(net.IP, net.IPv6len)
		copy(ip, raw[:])
		return ip
	default:
		return nil
	}
}

func protoName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return strconv.Itoa(int(proto))
	}
}

func ntohs(v uint16) uint16 {
	var raw [2]byte
	binary.LittleEndian.PutUint16(raw[:], v)
	return binary.BigEndian.Uint16(raw[:])
}
