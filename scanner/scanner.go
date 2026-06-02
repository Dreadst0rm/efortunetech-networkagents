package scanner

import (
	"fmt"
	"os/exec"
	"strings"
)

// RiskLevel represents the severity of a suspicious connection.
type RiskLevel string

const (
	RiskLow     RiskLevel = "low"
	RiskMedium  RiskLevel = "medium"
	RiskHigh    RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ConnectionRisk annotates a connection with risk analysis.
type ConnectionRisk struct {
	Connection
	RiskLevel    RiskLevel
	RiskReasons  []string
	IsSuspicious bool
}

type Connection struct {
	ProcessID  int
	Process    string
	Executable string
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
	Protocol   string
	State      string
	Direction  string // "outbound", "inbound", "unknown"
}

type ProcessInfo struct {
	PID     int
	Name    string
	enabled bool
}

func ScanAll() ([]Connection, []ProcessInfo, error) {
	procs, err := EnumerateProcesses()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to enumerate processes: %w", err)
	}

	connSet := make(map[int]*Connection)
	conns, err := GetNetConnections(connSet)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get network connections: %w", err)
	}

	// Correlate connections to processes via PID
	for i := range conns {
		for _, p := range procs {
			if conns[i].ProcessID == p.PID {
				conns[i].Process = p.Name
				break
			}
		}
		conns[i].Direction = determineDirection(&conns[i])
	}

	return conns, procs, nil
}

func EnumerateProcesses() ([]ProcessInfo, error) {
	out, err := exec.Command("wmic", "process", "get", "Name,ProcessId", "/format:list").Output()
	if err != nil {
		return nil, fmt.Errorf("wmic process failed: %w", err)
	}

	// wmic /format:list format:
	//   Name=xxx\n\nProcessId=1234\n\n\n\nName=yyy\n\nProcessId=5678
	// Within an entry: Name and ProcessId separated by 1 blank line
	// Between entries: multiple blank lines
	// Strategy: emit as soon as both Name and ProcessId are present
	lines := strings.Split(string(out), "\n")
	var procs []ProcessInfo
	current := ProcessInfo{enabled: false}
	for _, line := range lines {
		if strings.HasPrefix(line, "Name=") {
			current.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name="))
			current.enabled = true
		} else if strings.HasPrefix(line, "ProcessId=") {
			var pid int
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "ProcessId=")), "%d", &pid)
			current.PID = pid
			if current.enabled && current.PID >= 0 {
				procs = append(procs, current)
				current = ProcessInfo{enabled: false}
			}
		}
	}
	return procs, nil
}

func GetNetConnections(connSet map[int]*Connection) ([]Connection, error) {
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	var conns []Connection
	lines := strings.Split(string(out), "\n")
	inTable := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Active Connections") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}

		// Skip header/separator lines
		if strings.Contains(line, "-----") || line == "" || line == "Proto" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		proto := strings.ToUpper(parts[0])
		if proto != "TCP" && proto != "TCPV6" && proto != "UDP" && proto != "UDPV6" {
			continue
		}

		// Parse local address (might have multiple colons for IPv6)
		localAddr := parseWindowsAddr(parts[1])
		remoteAddr := parseWindowsAddr(parts[2])
		state := parts[3]
		pidStr := parts[4]

		var pid int
		fmt.Sscanf(pidStr, "%d", &pid)
		if pid < 0 {
			continue
		}

		c := Connection{
			ProcessID: pid,
			LocalAddr: localAddr.ip,
			LocalPort: localAddr.port,
			RemoteAddr: remoteAddr.ip,
			RemotePort: remoteAddr.port,
			Protocol:   proto,
			State:      state,
		}

		if connSet != nil {
			connSet[pid] = &c
		}
		conns = append(conns, c)
	}

	return conns, nil
}

type winAddr struct {
	ip   string
	port int
}

func parseWindowsAddr(s string) winAddr {
	// Windows format: ip:port  (e.g., 0.0.0.0:135 or [::]:0)
	if s == "*" {
		return winAddr{ip: "*", port: 0}
	}

	// Remove brackets for IPv6
	clean := s

	// Find last colon for port (handles IPv6 bracket notation)
	lastColon := strings.LastIndex(clean, ":")
	if lastColon == -1 {
		return winAddr{ip: clean, port: 0}
	}

	ipPart := clean[:lastColon]
	var port int
	fmt.Sscanf(clean[lastColon+1:], "%d", &port)

	return winAddr{ip: ipPart, port: port}
}

func determineDirection(c *Connection) string {
	if c.RemoteAddr == "*" || c.RemoteAddr == "0.0.0.0" {
		return "inbound"
	}
	if c.RemoteAddr == "" {
		return "inbound"
	}
	// IPv6 loopback and link-local
	if strings.HasPrefix(c.RemoteAddr, "[::") ||
		strings.HasPrefix(c.RemoteAddr, "::1") ||
		strings.HasPrefix(c.RemoteAddr, "fe80::") ||
		strings.HasPrefix(c.RemoteAddr, "fd") ||
		strings.HasPrefix(c.RemoteAddr, "ff") {
		return "internal"
	}
	// IPv4 private ranges
	if strings.HasPrefix(c.RemoteAddr, "127.") ||
		strings.HasPrefix(c.RemoteAddr, "192.168.") ||
		strings.HasPrefix(c.RemoteAddr, "10.") ||
		strings.HasPrefix(c.RemoteAddr, "172.") {
		return "internal"
	}
	return "outbound"
}

func IsSuspiciousState(state string) bool {
	suspicious := map[string]bool{
		"SYN_SENT":    true,
		"SYN_RECEIVED": true,
		"TIME_WAIT":   true,
		"CLOSE_WAIT":  true,
	}
	return suspicious[strings.ToUpper(state)]
}

func IsExternalIP(addr string) bool {
	if addr == "" || addr == "0.0.0.0" || addr == "*" {
		return false
	}
	// IPv6: reject all non-universal IPv6
	if strings.HasPrefix(addr, "[::") || strings.HasPrefix(addr, "[fe80::") ||
		strings.HasPrefix(addr, "[fd") || strings.HasPrefix(addr, "[ff") ||
		strings.HasPrefix(addr, "::1") || strings.HasPrefix(addr, "fe80::") ||
		strings.HasPrefix(addr, "fd") || strings.HasPrefix(addr, "ff") {
		return false
	}
	// IPv4: reject private ranges
	if strings.HasPrefix(addr, "127.") ||
		strings.HasPrefix(addr, "192.168.") ||
		strings.HasPrefix(addr, "10.") ||
		strings.HasPrefix(addr, "172.") {
		return false
	}
	return true
}

// SuspiciousProcessNames lists executable names that warrant extra scrutiny when
// they make external network connections.
var SuspiciousProcessNames = map[string]struct{}{
	"cmd.exe": {}, "powershell.exe": {}, "wscript.exe": {}, "cscript.exe": {},
	"wmic.exe": {}, "certutil.exe": {}, "bitsadmin.exe": {}, "dns.exe": {},
	"net.exe": {}, "ssh.exe": {}, "curl.exe": {}, "netsh.exe": {},
	"sc.exe": {}, "whoami.exe": {}, "mshta.exe": {}, "regsvr32.exe": {},
	"msbuild.exe": {}, "tasklist.exe": {}, "ipconfig.exe": {},
}

// IsSuspiciousProcess reports whether the given process name is in the
// SuspiciousProcessNames set.
func IsSuspiciousProcess(name string) bool {
	_, ok := SuspiciousProcessNames[strings.ToLower(name)]
	return ok
}

// CommonReverseProxyPorts are ports commonly used by C2, proxies, or malware.
var CommonReverseProxyPorts = map[int]struct{}{
	4444: {}, 5555: {}, 6666: {}, 6667: {}, 7777: {},
	8888: {}, 9999: {}, 1080: {}, 1081: {}, 3128: {},
	8080: {}, 8443: {}, 1337: {}, 9001: {}, 9050: {},
	9051: {}, 6660: {}, 6661: {}, 6662: {}, 6663: {},
	2525: {}, 4242: {}, 4243: {}, 4244: {}, 1234: {},
}

// IsSuspiciousPort reports whether the given port number is commonly associated
// with backdoors, proxies, or C2 infrastructure.
func IsSuspiciousPort(port int) bool {
	_, ok := CommonReverseProxyPorts[port]
	return ok
}

// IsTransitionState reports whether a TCP state indicates an anomalous or
// transitional connection that may signal scanning or covert channels.
func IsTransitionState(state string) bool {
	switch strings.ToUpper(state) {
	case "SYN_SENT", "SYN_RECEIVED", "TIME_WAIT", "CLOSE_WAIT":
		return true
	}
	return false
}

// AssessConnectionRisk evaluates a connection and returns a ConnectionRisk
// struct that combines all heuristic checks.
func AssessConnectionRisk(conns []Connection) []ConnectionRisk {
	// Count connections per process and per remote IP for heuristics.
	procCount := make(map[string]int)
	ipCount := make(map[string]int)
	for _, c := range conns {
		if c.Direction != "outbound" {
			continue
		}
		procCount[c.Process]++
		ipCount[c.RemoteAddr]++
	}

	var risks []ConnectionRisk
	for _, c := range conns {
		if c.Direction != "outbound" {
			continue
		}
		var (
			risk  RiskLevel
			reasons []string
		)

		// --- 1. Suspicious port detection ---
		if IsSuspiciousPort(c.RemotePort) {
			reasons = append(reasons, fmt.Sprintf("suspicious port %d", c.RemotePort))
		}

		// --- 2. Process name heuristic ---
		if IsSuspiciousProcess(c.Process) {
			reasons = append(reasons, fmt.Sprintf("suspicious process: %s", c.Process))
		}

		// --- 3. Transition-state heuristic ---
		if IsTransitionState(c.State) {
			reasons = append(reasons, fmt.Sprintf("connection state: %s", c.State))
		}

		// --- 4. Per-IP connection count heuristic ---
		if count := ipCount[c.RemoteAddr]; count >= 5 {
			reasons = append(reasons, fmt.Sprintf("high connection count to %s (%d)", c.RemoteAddr, count))
		}

		// --- 5. Per-process connection count heuristic ---
		if count := procCount[c.Process]; count >= 5 {
			reasons = append(reasons, fmt.Sprintf("high outbound connection count for %s (%d)", c.Process, count))
		}

		// --- Assign risk level ---
		switch {
		case len(reasons) >= 3:
			risk = RiskCritical
		case len(reasons) >= 2:
			risk = RiskHigh
		case len(reasons) == 1:
			risk = RiskMedium
		}

		// Only flag as suspicious if any heuristic triggered.
		isSuspicious := risk != RiskLow
		if !isSuspicious {
			continue
		}

		risks = append(risks, ConnectionRisk{
			Connection:  c,
			RiskLevel:   risk,
			RiskReasons: reasons,
			IsSuspicious: isSuspicious,
		})
	}

	return risks
}
