package main

import (
	"net"
	"testing"
	"time"
)

func TestParseProcNetTCPLine(t *testing.T) {
	line := `0: 0500000A:D431 64771A02:01BB 01 00000000:00000000 02:00000355 00000000 1000 0 12345 2 0000000000000000 20 4 30 10 -1`

	conn, ok := parseProcNetTCPLine(line, false)
	if !ok {
		t.Fatal("expected established connection")
	}
	if conn.Local != "10.0.0.5:54321" {
		t.Fatalf("unexpected local addr: %q", conn.Local)
	}
	if conn.Remote != "2.26.119.100:443" {
		t.Fatalf("unexpected remote addr: %q", conn.Remote)
	}
}

func TestParseProcNetTCPLineSkipsNonEstablished(t *testing.T) {
	line := `0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000`

	_, ok := parseProcNetTCPLine(line, false)
	if ok {
		t.Fatal("expected listener to be skipped")
	}
}

func TestParseProcNetIPv6(t *testing.T) {
	got, ok := parseProcNetAddr("00000000000000000000000001000000:01BB", true)
	if !ok {
		t.Fatal("expected IPv6 address to parse")
	}
	if got != "[::1]:443" {
		t.Fatalf("unexpected IPv6 addr: %q", got)
	}
}

func TestRemoteIPFromAddr(t *testing.T) {
	tests := map[string]string{
		"2.26.119.100:443":      "2.26.119.100",
		"2.26.119.100.443":      "2.26.119.100",
		"[2001:db8::10]:443":    "2001:db8::10",
		"[fe80::1%eth0]:443":    "fe80::1",
		"tcp:185.65.151.81.443": "185.65.151.81",
		"*:*":                   "",
	}

	for input, want := range tests {
		got := remoteIPFromAddr(input)
		if got != want {
			t.Fatalf("remoteIPFromAddr(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseLSOFConnections(t *testing.T) {
	output := `COMMAND     PID    USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ssh        5327 user    4u  IPv4 0x1    0t0  TCP 10.88.1.135:57696->10.0.3.223:22 (ESTABLISHED)
Code\x20H 21686 user   22u  IPv4 0x2    0t0  TCP 240.0.0.2:61225->52.168.112.66:443 (ESTABLISHED)
`

	conns := parseLSOFConnections(output)
	if len(conns) != 2 {
		t.Fatalf("expected 2 connections, got %d", len(conns))
	}
	if conns[0].Local != "10.88.1.135:57696" {
		t.Fatalf("unexpected local addr: %q", conns[0].Local)
	}
	if conns[0].Remote != "10.0.3.223:22" {
		t.Fatalf("unexpected remote addr: %q", conns[0].Remote)
	}
	if conns[0].PID != "ssh(5327)" {
		t.Fatalf("unexpected process: %q", conns[0].PID)
	}
	if conns[1].PID != `Code\x20H(21686)` {
		t.Fatalf("unexpected escaped process: %q", conns[1].PID)
	}
}

func TestGroupConnectionsFromProc(t *testing.T) {
	conn, ok := parseProcNetTCPLine(`0: 0500000A:D431 64771A02:01BB 01 00000000:00000000 02:00000355 00000000 1000 0 12345 2 0000000000000000 20 4 30 10 -1`, false)
	if !ok {
		t.Fatal("expected established connection")
	}
	conns := []connection{conn}
	grouped := groupConnections(conns)
	if len(grouped["2.26.119.100"]) != 1 {
		t.Fatalf("expected connection grouped by remote IP, got %#v", grouped)
	}
}

func TestGatewayIPPairToEvent(t *testing.T) {
	manager := &captureManager{mode: modeGateway, localIPs: map[string]struct{}{}}

	events := manager.gatewayIPPairToEvents(net.ParseIP("10.147.17.23"), net.ParseIP("8.8.8.8"), 120)
	if len(events) != 2 {
		t.Fatalf("expected two gateway events, got %#v", events)
	}
	out := events[0]
	if out.remoteIP != "10.147.17.23" || out.dir != dirOut || out.bytes != 120 {
		t.Fatalf("unexpected outbound event: %#v", out)
	}
	in := events[1]
	if in.remoteIP != "8.8.8.8" || in.dir != dirIn || in.bytes != 120 {
		t.Fatalf("unexpected inbound event: %#v", in)
	}
}

func TestGatewaySkipsLocalNodeIP(t *testing.T) {
	manager := &captureManager{
		mode:     modeGateway,
		localIPs: map[string]struct{}{"10.147.17.1": {}},
	}

	events := manager.gatewayIPPairToEvents(net.ParseIP("10.147.17.1"), net.ParseIP("10.147.17.23"), 100)
	if len(events) != 1 {
		t.Fatalf("expected only remote client event, got %#v", events)
	}
	if events[0].remoteIP != "10.147.17.23" || events[0].dir != dirIn {
		t.Fatalf("unexpected event: %#v", events[0])
	}
}

func TestRateFormattingUsesBits(t *testing.T) {
	if got := humanMbitRate(125000); got != "1.00Mbit/s" {
		t.Fatalf("humanMbitRate(125000) = %q, want 1.00Mbit/s", got)
	}
	if got := humanBitRate(125000); got != "1.0Mbit/s" {
		t.Fatalf("humanBitRate(125000) = %q, want 1.0Mbit/s", got)
	}
	if got := humanBitRate(1024); got != "8.2Kbit/s" {
		t.Fatalf("humanBitRate(1024) = %q, want 8.2Kbit/s", got)
	}
}

func TestRollingRatesForWindow(t *testing.T) {
	now := time.Unix(100, 0)
	stats := &ipStats{
		History: []statSample{
			{At: now.Add(-5 * time.Second), InBytes: 0, OutBytes: 0},
			{At: now.Add(-3 * time.Second), InBytes: 300, OutBytes: 600},
			{At: now, InBytes: 900, OutBytes: 1200},
		},
	}

	inRate, outRate := stats.ratesForWindow(now, 3*time.Second)
	if inRate != 200 {
		t.Fatalf("inRate = %v, want 200", inRate)
	}
	if outRate != 200 {
		t.Fatalf("outRate = %v, want 200", outRate)
	}
}
