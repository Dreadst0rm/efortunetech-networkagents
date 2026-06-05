package scanner

import (
	"fmt"
	"net"
	"strings"

	"networksentinel/config"
	"networksentinel/processinfo"
	"networksentinel/threatintel"
)

// AssessConnectionRiskWithThreatIntel evaluates a connection with threat intelligence matching.
func AssessConnectionRiskWithThreatIntel(conns []Connection, secInfo map[int]processinfo.Info, cfg *config.Config, tiDB *threatintel.ThreatIntelDB) []ConnectionRisk {
	risks := AssessConnectionRisk(conns, secInfo, cfg)

	if tiDB == nil {
		return risks
	}

	for i, r := range risks {
		match := tiDB.LookupConnection(r.RemoteAddr)
		if match != nil {
			for _, ioc := range match.IOCs {
				r.RiskReasons = append(r.RiskReasons, fmt.Sprintf("THREAT_INTEL: %s (%s) confidence=%d country=%s tags=[%s]", ioc.MalwareFamily, ioc.Source, ioc.Confidence, ioc.Country, strings.Join(ioc.Tags, ", ")))
				if ioc.Confidence >= 90 {
					r.RiskLevel = RiskCritical
				} else if ioc.Confidence >= 80 {
					if r.RiskLevel == RiskLow || r.RiskLevel == RiskMedium {
						r.RiskLevel = RiskHigh
					}
				}
			}
			risks[i] = r
		}
	}

	return risks
}

// RiskLevel represents the severity of a suspicious connection.
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ConnectionRisk annotates a connection with risk analysis.
type ConnectionRisk struct {
	Connection
	RiskLevel     RiskLevel
	RiskReasons   []string
	IsSuspicious  bool
	IsWhitelisted bool
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
	DNSName    string // resolved domain name from reverse DNS lookup
}

type ProcessEntry struct {
	PID  int
	Name string
}

func ScanAll(cfg *config.Config) ([]Connection, []ProcessEntry, map[int]processinfo.Info, error) {
	procs, err := enumerateProcesses()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to enumerate processes: %w", err)
	}

	connSet := make(map[int]*Connection)
	conns, err := getNetConnections(connSet)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get network connections: %w", err)
	}

	// Correlate connections to processes via PID
	procMap := make(map[int]string)
	for _, p := range procs {
		procMap[p.PID] = p.Name
	}
	for i := range conns {
		if name, ok := procMap[conns[i].ProcessID]; ok {
			conns[i].Process = name
		}
		conns[i].Direction = determineDirection(&conns[i])
	}

	// Filter excluded PIDs and processes
	var filtered []Connection
	for _, c := range conns {
		if cfg.IsExcludedPID(c.ProcessID) || cfg.IsExcludedProcess(c.Process) {
			continue
		}
		filtered = append(filtered, c)
	}
	conns = filtered

	// Gather process security context for unique PIDs
	pidSet := make(map[int]bool)
	for _, c := range conns {
		pidSet[c.ProcessID] = true
	}
	secInfo := make(map[int]processinfo.Info)
	for pid := range pidSet {
		info, err := processinfo.GetProcessInfo(pid)
		if err == nil {
			secInfo[pid] = info
		}
	}

	return conns, procs, secInfo, nil
}

func determineDirection(c *Connection) string {
	if c.RemoteAddr == "*" || c.RemoteAddr == "0.0.0.0" || c.RemoteAddr == "" {
		return "inbound"
	}
	if IsPrivateIP(c.RemoteAddr) {
		return "internal"
	}
	return "outbound"
}

func IsExternalIP(addr string) bool {
	return !IsPrivateIP(addr)
}

// IsPrivateIP returns true if addr is a loopback, private, or link-local address.
// It handles IPv4 ranges (127.x, 192.168.x, 10.x, 172.16-31.x) and IPv6
// (loopback, link-local, unique-local, multicast). Brackets are stripped for IPv6.
func IsPrivateIP(addr string) bool {
	if addr == "" || addr == "0.0.0.0" || addr == "*" {
		return true
	}
	clean := addr
	if strings.HasPrefix(clean, "[") {
		idx := strings.Index(clean, "]")
		if idx > 1 {
			clean = clean[1:idx]
		}
	}
	ip := net.ParseIP(clean)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast()
}

// SuspiciousProcessNames lists executable names that warrant extra scrutiny when
// they make external network connections. Platform-aware — each OS builds its own set.
func SuspiciousProcessNamesList() map[string]struct{} {
	return suspiciousProcsForOS()
}

// suspiciousProcsLower is a pre-computed lowercase map for O(1) case-insensitive lookups.
var suspiciousProcsLower map[string]struct{}

func init() {
	suspiciousProcsLower = make(map[string]struct{})
	for n := range suspiciousProcsForOS() {
		suspiciousProcsLower[strings.ToLower(n)] = struct{}{}
	}
}

func IsSuspiciousProcess(name string) bool {
	_, ok := suspiciousProcsLower[strings.ToLower(name)]
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
func AssessConnectionRisk(conns []Connection, secInfo map[int]processinfo.Info, cfg *config.Config) []ConnectionRisk {
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

	// Pre-allocate with capacity to avoid reallocation.
	risks := make([]ConnectionRisk, 0, len(conns))
	for _, c := range conns {
		if c.Direction != "outbound" {
			continue
		}

		// Whitelisted IPs skip suspicious port and process heuristics.
		isWhitelisted := cfg.IsWhitelistedIP(c.RemoteAddr)

		// Use a short buffer on-stack for reasons to avoid heap allocation
		// when no heuristics fire. Max 6 heuristics.
		var reasons [6]string
		count := 0

		// --- 1. Suspicious port detection ---
		if !isWhitelisted && IsSuspiciousPort(c.RemotePort) {
			reasons[count] = "suspicious port " + itoa(c.RemotePort)
			count++
		}

		// --- 2. Process name heuristic ---
		if !isWhitelisted && IsSuspiciousProcess(c.Process) {
			reasons[count] = "suspicious process: " + c.Process
			count++
		}

		// --- 3. Transition-state heuristic ---
		if IsTransitionState(c.State) {
			reasons[count] = "connection state: " + c.State
			count++
		}

		// --- 4. Per-IP connection count heuristic ---
		if ipCount[c.RemoteAddr] >= cfg.Thresholds.MinIPConnections {
			reasons[count] = "high connection count to " + c.RemoteAddr + " (" + itoa(ipCount[c.RemoteAddr]) + ")"
			count++
		}

		// --- 5. Per-process connection count heuristic ---
		if procCount[c.Process] >= cfg.Thresholds.MinProcessConnections {
			reasons[count] = "high outbound connection count for " + c.Process + " (" + itoa(procCount[c.Process]) + ")"
			count++
		}

		// --- 6. Privilege escalation chain detection ---
		if info, ok := secInfo[c.ProcessID]; ok {
			if reason := privEscReason(info); reason != "" {
				reasons[count] = reason
				count++
			}
		}

		// --- Assign risk level ---
		switch {
		case count >= cfg.Thresholds.CriticalThreshold:
			risks = append(risks, ConnectionRisk{
				Connection:    c,
				RiskLevel:     RiskCritical,
				RiskReasons:   reasons[:count],
				IsSuspicious:  true,
				IsWhitelisted: isWhitelisted,
			})
		case count >= cfg.Thresholds.HighThreshold:
			risks = append(risks, ConnectionRisk{
				Connection:    c,
				RiskLevel:     RiskHigh,
				RiskReasons:   reasons[:count],
				IsSuspicious:  true,
				IsWhitelisted: isWhitelisted,
			})
		case count == 1:
			risks = append(risks, ConnectionRisk{
				Connection:    c,
				RiskLevel:     RiskMedium,
				RiskReasons:   reasons[:count],
				IsSuspicious:  true,
				IsWhitelisted: isWhitelisted,
			})
		}
		// count == 0 → no heuristic triggered, skip.
	}

	return risks
}

// itoa converts an int to a string without allocating.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// privEscReason returns a non-empty string describing a privilege escalation
// risk for the given process info, or an empty string if no escalation is detected.
// It checks the highest-severity condition first so only one reason is returned.
func privEscReason(info processinfo.Info) string {
	isElevated := info.PrivLevel == processinfo.Elevated || info.PrivLevel == processinfo.SYSTEM
	if !isElevated {
		return ""
	}
	isTempPath := processinfo.IsSuspiciousPath(info.ExePath)
	if !info.IsSigned && isTempPath {
		return "PRIVILEGE ESCALATION: elevated + unsigned + temp path"
	}
	if !info.IsSigned {
		return "elevated + unsigned binary: " + info.ExePath
	}
	if isTempPath {
		return "elevated process from temp path: " + info.ExePath
	}
	return ""
}
