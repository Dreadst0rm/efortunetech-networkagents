package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"networksentinel/scanner"
	"networksentinel/systeminfo"
)

// Data bundles all data needed for a report.
type Data struct {
	System      *systeminfo.SystemDetails
	Connections []scanner.Connection
	Processes   []scanner.ProcessInfo
	Risks       []scanner.ConnectionRisk
}

// Findings summarizes the risk analysis.
type Findings struct {
	TotalOutbound    int
	ExternalEndpoints int
	SuspiciousPorts   int
	SuspiciousProcs   int
	HighestRisk       scanner.RiskLevel
	CriticalCount     int
	HighCount         int
	MediumCount       int
	LowCount          int
}

// GenerateMarkdown writes a Markdown report to disk.
func GenerateMarkdown(data Data, filename string) error {
	var sb strings.Builder

	sb.WriteString("# Process Network Analysis Report\n\n")
	sb.WriteString(fmt.Sprintf("**Scan time:** %s\n\n", time.Now().Format(time.RFC1123)))

	// System overview
	sb.WriteString("## System Information\n\n")
	if data.System != nil {
		sb.WriteString("| Field | Value |\n")
		sb.WriteString("|-------|-----|\n")
		sb.WriteString(fmt.Sprintf("| Hostname | `%s` |\n", data.System.Hostname))
		sb.WriteString(fmt.Sprintf("| OS | `%s` |\n", data.System.OSPlatform))
		if len(data.System.LocalIPs) > 0 {
			sb.WriteString(fmt.Sprintf("| Local IPs | `%s` |\n", strings.Join(data.System.LocalIPs, ", ")))
		}
	}
	sb.WriteString("\n")

	// Network connections summary
	sb.WriteString("## Network Connections Summary\n\n")
	if len(data.Connections) == 0 {
		sb.WriteString("No network connections found.\n\n")
	} else {
		outbound := 0
		inbound := 0
		stateCounts := make(map[string]int)
		for _, c := range data.Connections {
			stateCounts[c.State]++
			if c.Direction == "outbound" {
				outbound++
			} else {
				inbound++
			}
		}
		sb.WriteString("| Metric | Count |\n")
		sb.WriteString("|--------|--+--|\n")
		sb.WriteString(fmt.Sprintf("| Total connections | %d |\n", len(data.Connections)))
		sb.WriteString(fmt.Sprintf("| Outbound | %d |\n", outbound))
		sb.WriteString(fmt.Sprintf("| Inbound | %d |\n", inbound))
		var states []string
		for s, n := range stateCounts {
			states = append(states, fmt.Sprintf("%s=%d", s, n))
		}
		sort.Strings(states)
		sb.WriteString(fmt.Sprintf("| Connection states | %s |\n", strings.Join(states, "; ") ))
	}

	// External endpoints
	sb.WriteString("\n## External Endpoints\n\n")
	extMap := make(map[string][]int)
	for _, c := range data.Connections {
		if IsExternal(c) && c.Direction == "outbound" {
			if _, ok := extMap[c.RemoteAddr]; !ok {
				extMap[c.RemoteAddr] = []int{}
			}
			exists := false
			for _, p := range extMap[c.RemoteAddr] {
				if p == c.RemotePort {
					exists = true
					break
				}
			}
			if !exists {
				extMap[c.RemoteAddr] = append(extMap[c.RemoteAddr], c.RemotePort)
			}
		}
	}
	if len(extMap) == 0 {
		sb.WriteString("No external outbound connections found.\n\n")
	} else {
		var addrs []string
		for addr := range extMap {
			addrs = append(addrs, addr)
		}
		sort.Strings(addrs)
		sb.WriteString("| Remote Address | Ports |\n")
		sb.WriteString("|------|----|\n")
		for _, addr := range addrs {
			var ports []string
			for _, p := range extMap[addr] {
				ports = append(ports, fmt.Sprintf("%d", p))
			}
			sort.Strings(ports)
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` |\n", addr, strings.Join(ports, ", ")))
		}
	}

	// Suspicious connections
	sb.WriteString("\n## Suspicious Connections\n\n")
	var suspiciousConns []scanner.Connection
	for _, c := range data.Connections {
		if IsSuspicious(c) {
			suspiciousConns = append(suspiciousConns, c)
		}
	}
	if len(suspiciousConns) == 0 {
		sb.WriteString("No suspicious connections found.\n\n")
	} else {
		sb.WriteString("| Process | PID | Remote Address | Port | State |\n")
		sb.WriteString("|---------|---|-+------|--+---|---+---|\n")
		for _, c := range suspiciousConns {
			sb.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | %d | `%s` |\n", c.Process, c.ProcessID, c.RemoteAddr, c.RemotePort, c.State))
		}
	}

	// Risk summary
	sb.WriteString("\n## Risk Analysis Summary\n\n")
	if len(data.Risks) == 0 {
		sb.WriteString("No suspicious outbound connections detected.\n\n")
	} else {
		// Count risk levels
		critical, high, medium, low := 0, 0, 0, 0
		for _, r := range data.Risks {
			switch r.RiskLevel {
			case scanner.RiskCritical:
				critical++
			case scanner.RiskHigh:
				high++
			case scanner.RiskMedium:
				medium++
			case scanner.RiskLow:
				low++
			}
		}
		sb.WriteString("| Risk Level | Count |\n")
		sb.WriteString("|-----------|------|\n")
		sb.WriteString(fmt.Sprintf("| **CRITICAL** | %d |\n", critical))
		sb.WriteString(fmt.Sprintf("| **HIGH** | %d |\n", high))
		sb.WriteString(fmt.Sprintf("| **MEDIUM** | %d |\n", medium))
		sb.WriteString(fmt.Sprintf("| **LOW** | %d |\n", low))
		sb.WriteString(fmt.Sprintf("| **TOTAL** | %d |\n", len(data.Risks)))
	}

	// Top processes by network activity
	sb.WriteString("\n## Top Processes by Network Activity\n\n")
	procCount := make(map[string]int)
	procPID := make(map[string]int)
	for _, c := range data.Connections {
		procCount[c.Process]++
		procPID[c.Process] = c.ProcessID
	}
	var procs []string
	for p := range procCount {
		procs = append(procs, p)
	}
	sort.Slice(procs, func(i, j int) bool {
		return procCount[procs[i]] > procCount[procs[j]]
	})
	if len(procs) == 0 {
		sb.WriteString("No process data available.\n")
	} else {
		sb.WriteString("| Process | PID | Connections |\n")
		sb.WriteString("|---------|---|-----------|\n")
		for _, p := range procs[:min(20, len(procs))] {
			sb.WriteString(fmt.Sprintf("| `%s` | %d | %d |\n", p, procPID[p], procCount[p]))
		}
	}

	// Findings summary
	findings := countFindings(data.Connections, data.Risks)
	sb.WriteString("\n## Key Findings\n\n")
	sb.WriteString("| Finding | Count |\n")
	sb.WriteString("|---------|------|\n")
	sb.WriteString(fmt.Sprintf("| Outbound connections | %d |\n", findings.TotalOutbound))
	sb.WriteString(fmt.Sprintf("| External endpoints | %d |\n", findings.ExternalEndpoints))
	sb.WriteString(fmt.Sprintf("| Suspicious ports | %d |\n", findings.SuspiciousPorts))
	sb.WriteString(fmt.Sprintf("| Suspicious processes | %d |\n", findings.SuspiciousProcs))
	sb.WriteString(fmt.Sprintf("| Critical risk connections | %d |\n", findings.CriticalCount))
	sb.WriteString(fmt.Sprintf("| High risk connections | %d |\n", findings.HighCount))
	sb.WriteString(fmt.Sprintf("| Medium risk connections | %d |\n", findings.MediumCount))
	sb.WriteString(fmt.Sprintf("| Low risk connections | %d |\n", findings.LowCount))

	return os.WriteFile(filename, []byte(sb.String()), 0644)
}

// IsExternal returns true if the connection goes to an external (non-private) IP.
func IsExternal(c scanner.Connection) bool {
	if c.RemoteAddr == "" || c.RemoteAddr == "0.0.0.0" || c.RemoteAddr == "*" {
		return false
	}
	// Strip brackets for IPv6
	ip := c.RemoteAddr
	if strings.HasPrefix(ip, "[") && strings.Index(ip, "]") > 0 {
		ip = ip[1:strings.Index(ip, "]")]
	}
	return !strings.HasPrefix(ip, "127.") &&
		!strings.HasPrefix(ip, "192.168.") &&
		!strings.HasPrefix(ip, "10.") &&
		!strings.HasPrefix(ip, "172.") &&
		!strings.HasPrefix(ip, "[::") &&
		!strings.HasPrefix(ip, "[fe80::") &&
		!strings.HasPrefix(ip, "[fd") &&
		!strings.HasPrefix(ip, "[ff") &&
		!strings.HasPrefix(ip, "fe80::") &&
		!strings.HasPrefix(ip, "fd") &&
		!strings.HasPrefix(ip, "::1")
}

// IsSuspicious returns true if the connection target is outside the local machine.
func IsSuspicious(c scanner.Connection) bool {
	return !IsLocal(c.RemoteAddr)
}

// IsLocal returns true for loopback or private IP ranges (including IPv6).
func IsLocal(addr string) bool {
	if addr == "" || addr == "0.0.0.0" || addr == "*" {
		return true
	}
	// Strip brackets for IPv6
	clean := addr
	if strings.HasPrefix(clean, "[") && strings.Index(clean, "]") > 0 {
		clean = clean[1:strings.Index(clean, "]")]
	}
	// IPv6: loopback and link-local
	if clean == "::1" || clean == "::" ||
		strings.HasPrefix(clean, "fe80::") || strings.HasPrefix(clean, "fd") ||
		strings.HasPrefix(clean, "ff") {
		return true
	}
	// IPv4 private ranges
	return strings.HasPrefix(addr, "127.") ||
		strings.HasPrefix(addr, "192.168.") ||
		strings.HasPrefix(addr, "10.") ||
		strings.HasPrefix(addr, "172.")
}

// SuspiciousProcessNames is the set of process names that warrant extra scrutiny.
var SuspiciousProcessNames = map[string]struct{}{
	"cmd.exe":      {},
	"powershell.exe": {},
	"wscript.exe":  {},
	"cscript.exe":  {},
	"wmic.exe":     {},
	"certutil.exe": {},
	"bitsadmin.exe": {},
	"dns.exe":      {},
	"net.exe":      {},
	"ssh.exe":      {},
	"curl.exe":     {},
	"netsh.exe":    {},
	"sc.exe":       {},
	"whoami.exe":   {},
	"mshta.exe":    {},
}

// IsSuspiciousProcess checks whether the process name is one that warrants scrutiny.
func IsSuspiciousProcess(name string) bool {
	_, ok := SuspiciousProcessNames[strings.ToLower(name)]
	return ok
}

func countFindings(conns []scanner.Connection, risks []scanner.ConnectionRisk) Findings {
	f := Findings{}
	seenEndpoints := make(map[string]bool)
	seenSuspicious := make(map[int]bool)
	for _, c := range conns {
		if c.Direction == "outbound" && c.RemoteAddr != "" {
			f.TotalOutbound++
		}
		if IsExternal(c) && c.Direction == "outbound" {
			key := fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort)
			if !seenEndpoints[key] {
				f.ExternalEndpoints++
				seenEndpoints[key] = true
			}
		}
		if isSuspiciousPort(c.RemotePort) {
			f.SuspiciousPorts++
		}
		if IsSuspiciousProcess(c.Process) {
			seenSuspicious[c.ProcessID] = true
		}
	}
	f.SuspiciousProcs = len(seenSuspicious)

	for _, r := range risks {
		switch r.RiskLevel {
		case scanner.RiskCritical:
			f.CriticalCount++
		case scanner.RiskHigh:
			f.HighCount++
		case scanner.RiskMedium:
			f.MediumCount++
		case scanner.RiskLow:
			f.LowCount++
		}
		if f.HighestRisk == "" || r.RiskLevel > f.HighestRisk {
			f.HighestRisk = r.RiskLevel
		}
	}
	return f
}

func isSuspiciousPort(port int) bool {
	suspiciousPorts := map[int]struct{}{
		4444: {}, 5555: {}, 6666: {}, 6667: {}, 7777: {},
		8888: {}, 9999: {}, 1080: {}, 1081: {}, 3128: {},
		8080: {}, 8443: {}, 1337: {}, 9001: {}, 9050: {},
		9051: {}, 6660: {}, 6661: {}, 6662: {}, 6663: {},
		2525: {}, 4242: {}, 4243: {}, 4244: {}, 1234: {},
	}
	_, ok := suspiciousPorts[port]
	return ok
}
