package main

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

type connection struct {
	Proto  string
	Local  string
	Remote string
	State  string
	PID    string
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
