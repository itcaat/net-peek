//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
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

	var links []link.Link
	cleanup := func() {
		for _, l := range links {
			_ = l.Close()
		}
		_ = objs.Close()
	}

	for _, iface := range ifaces {
		ingress, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   objs.IngressAccount,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			cleanup()
			return fmt.Errorf("%s: attach eBPF TC ingress: %w", iface.Name, err)
		}
		links = append(links, ingress)

		egress, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   objs.EgressAccount,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			cleanup()
			return fmt.Errorf("%s: attach eBPF TC egress: %w", iface.Name, err)
		}
		links = append(links, egress)
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
