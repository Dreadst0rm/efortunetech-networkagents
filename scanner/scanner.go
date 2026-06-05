package scanner

import (
	"fmt"
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

// PrivilegeLevel represents the severity of a process privilege.
type PrivilegeLevel string

const (
	PrivElevated PrivilegeLevel = "elevated"
	PrivStandard PrivilegeLevel = "standard"
	PrivSystem   PrivilegeLevel = "system"
	PrivUnknown  PrivilegeLevel = "unknown"
)

// RiskLevel represents the severity of a suspicious connection.
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ProcessSecurityInfo carries per-PID security context for Phase 3.
type ProcessSecurityInfo struct {
	PID        int
	Process    string
	Username   string
	PrivLevel  PrivilegeLevel
	IsElevated bool
	IsSigned   bool
	Signer     string
	ExePath    string
	IsTempPath bool
	IsSYSTEM   bool
	IsAdmin    bool
}

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
	PID     int
	Name    string
	enabled bool
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
	for i := range conns {
		for _, p := range procs {
			if conns[i].ProcessID == p.PID {
				conns[i].Process = p.Name
				break
			}
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

func IsSuspiciousState(state string) bool {
	suspicious := map[string]bool{
		"SYN_SENT":     true,
		"SYN_RECEIVED": true,
		"TIME_WAIT":    true,
		"CLOSE_WAIT":   true,
	}
	return suspicious[strings.ToUpper(state)]
}

func IsExternalIP(addr string) bool {
	return !IsPrivateIP(addr)
}

func IsPrivatePrefix(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	rest := strings.TrimPrefix(s, prefix)
	return len(rest) > 0 && rest[0] == '.'
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
	if clean == "::1" || clean == "::" ||
		strings.HasPrefix(clean, "fe80::") || strings.HasPrefix(clean, "fd") ||
		strings.HasPrefix(clean, "ff") {
		return true
	}
	return strings.HasPrefix(clean, "127.") ||
		strings.HasPrefix(clean, "192.168.") ||
		strings.HasPrefix(clean, "10.") ||
		IsPrivatePrefix(clean, "172")
}

// SuspiciousProcessNames lists executable names that warrant extra scrutiny when
// they make external network connections. Platform-aware — each OS builds its own set.
func SuspiciousProcessNamesList() map[string]struct{} {
	return suspiciousProcsForOS()
}

func IsSuspiciousProcess(name string) bool {
	for n := range SuspiciousProcessNamesList() {
		if strings.ToLower(n) == strings.ToLower(name) {
			return true
		}
	}
	return false
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

	var risks []ConnectionRisk
	for _, c := range conns {
		if c.Direction != "outbound" {
			continue
		}
		var (
			risk    RiskLevel
			reasons []string
		)

		// Whitelisted IPs skip suspicious port and process heuristics
		isWhitelisted := cfg.IsWhitelistedIP(c.RemoteAddr)

		// --- 1. Suspicious port detection ---
		if !isWhitelisted && IsSuspiciousPort(c.RemotePort) {
			reasons = append(reasons, fmt.Sprintf("suspicious port %d", c.RemotePort))
		}

		// --- 2. Process name heuristic ---
		if !isWhitelisted && IsSuspiciousProcess(c.Process) {
			reasons = append(reasons, fmt.Sprintf("suspicious process: %s", c.Process))
		}

		// --- 3. Transition-state heuristic ---
		if IsTransitionState(c.State) {
			reasons = append(reasons, fmt.Sprintf("connection state: %s", c.State))
		}

		// --- 4. Per-IP connection count heuristic ---
		if count := ipCount[c.RemoteAddr]; count >= cfg.Thresholds.MinIPConnections {
			reasons = append(reasons, fmt.Sprintf("high connection count to %s (%d)", c.RemoteAddr, count))
		}

		// --- 5. Per-process connection count heuristic ---
		if count := procCount[c.Process]; count >= cfg.Thresholds.MinProcessConnections {
			reasons = append(reasons, fmt.Sprintf("high outbound connection count for %s (%d)", c.Process, count))
		}

		// --- 6. Privilege escalation chain detection ---
		if info, ok := secInfo[c.ProcessID]; ok {
			isElevated := info.PrivLevel == processinfo.Elevated || info.PrivLevel == processinfo.SYSTEM
			isTempPath := processinfo.IsSuspiciousPath(info.ExePath)
			if isElevated && !info.IsSigned && isTempPath {
				reasons = append(reasons, "PRIVILEGE ESCALATION: elevated + unsigned + temp path")
			} else if isElevated && !info.IsSigned {
				reasons = append(reasons, fmt.Sprintf("elevated + unsigned binary: %s", info.ExePath))
			} else if isElevated && isTempPath {
				reasons = append(reasons, fmt.Sprintf("elevated process from temp path: %s", info.ExePath))
			}
		}

		// --- Assign risk level ---
		switch {
		case len(reasons) >= cfg.Thresholds.CriticalThreshold:
			risk = RiskCritical
		case len(reasons) >= cfg.Thresholds.HighThreshold:
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
			Connection:    c,
			RiskLevel:     risk,
			RiskReasons:   reasons,
			IsSuspicious:  isSuspicious,
			IsWhitelisted: isWhitelisted,
		})
	}

	return risks
}
