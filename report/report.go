package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"networksentinel/baseline"
	"networksentinel/dns"
	"networksentinel/processinfo"
	"networksentinel/scanner"
	"networksentinel/systeminfo"
	"networksentinel/version"
)

// WhitelistedIP represents a whitelisted IP with its comment.
type WhitelistedIP struct {
	IP      string
	Comment string
}

// Data bundles all data needed for a report.
type Data struct {
	System      *systeminfo.SystemDetails
	Connections []scanner.Connection
	Processes   []scanner.ProcessEntry
	Risks       []scanner.ConnectionRisk
	Security    map[int]processinfo.Info
	Baseline    baseline.DiffResult
	Whitelist   []WhitelistedIP
	DNSQueries  *dns.CaptureResult
}

// Findings summarizes the risk analysis.
type Findings struct {
	TotalOutbound       int
	ExternalEndpoints   int
	SuspiciousPorts     int
	SuspiciousProcs     int
	HighestRisk         scanner.RiskLevel
	CriticalCount       int
	HighCount           int
	MediumCount         int
	LowCount            int
	PrivEscalationCount int
	WhitelistedCount    int
}

// GenerateMarkdown writes a Markdown report to disk.
func GenerateMarkdown(data Data, filename string) error {
	var sb strings.Builder

	sb.WriteString("# Process Network Analysis Report\n\n")
	sb.WriteString(fmt.Sprintf("**Version:** %s | **Scan time:** %s\n\n", version.Version, time.Now().Format(time.RFC1123)))

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
		sb.WriteString("|--------|-------|\n")
		sb.WriteString(fmt.Sprintf("| Total connections | %d |\n", len(data.Connections)))
		sb.WriteString(fmt.Sprintf("| Outbound | %d |\n", outbound))
		sb.WriteString(fmt.Sprintf("| Inbound | %d |\n", inbound))
		var states []string
		for s, n := range stateCounts {
			states = append(states, fmt.Sprintf("%s=%d", s, n))
		}
		sort.Strings(states)
		sb.WriteString(fmt.Sprintf("| Connection states | %s |\n", strings.Join(states, "; ")))
	}

	// External endpoints
	sb.WriteString("\n## External Endpoints\n\n")
	extMap := make(map[string][]int)
	extDNS := make(map[string]string)
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
			if c.DNSName != "" && extDNS[c.RemoteAddr] == "" {
				extDNS[c.RemoteAddr] = c.DNSName
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
		sb.WriteString("| Remote Address | DNS Name | Ports |\n")
		sb.WriteString("|------|----------|----|\n")
		for _, addr := range addrs {
			var ports []string
			for _, p := range extMap[addr] {
				ports = append(ports, strconv.Itoa(p))
			}
			sort.Strings(ports)
			dnsName := extDNS[addr]
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` |\n", addr, dnsName, strings.Join(ports, ", ")))
		}
	}

	// DNS Queries
	sb.WriteString("\n## DNS Queries\n\n")
	if data.DNSQueries != nil && len(data.DNSQueries.Queries) > 0 {
		sb.WriteString("| Process | PID | Query Name |\n")
		sb.WriteString("|---------|---|----------|\n")
		for _, q := range data.DNSQueries.Queries {
			process := q.Process
			if process == "" {
				process = fmt.Sprintf("PID:%d", q.PID)
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %d | `%s` |\n", process, q.PID, q.QueryName))
		}
	} else {
		sb.WriteString("No DNS queries captured.\n\n")
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
		sb.WriteString("| Process | PID | DNS Name | Remote Address | Port | State |\n")
		sb.WriteString("|---------|---|----------|------|-----|-------|\n")
		for _, c := range suspiciousConns {
			sb.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | `%s` | %d | `%s` |\n", c.Process, c.ProcessID, c.DNSName, c.RemoteAddr, c.RemotePort, c.State))
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

	// Whitelisted connections
	sb.WriteString("\n## Whitelisted Connections\n\n")
	if len(data.Risks) > 0 {
		var whitelisted []scanner.ConnectionRisk
		for _, r := range data.Risks {
			if r.IsWhitelisted {
				whitelisted = append(whitelisted, r)
			}
		}
		if len(whitelisted) == 0 {
			sb.WriteString("No whitelisted connections detected.\n\n")
		} else {
			sb.WriteString("| Process | PID | Remote Address | Port | DNS Name | Comment |\n")
			sb.WriteString("|---------|---|------|-----|----------|---------|\n")
			for _, r := range whitelisted {
				comment := ""
				for _, w := range data.Whitelist {
					if strings.EqualFold(w.IP, r.Connection.RemoteAddr) {
						comment = sanitizeMarkdown(w.Comment)
						break
					}
				}
				sb.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | %d | `%s` | `%s` |\n",
					r.Process, r.ProcessID, r.RemoteAddr, r.RemotePort, r.DNSName, comment))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("No whitelisted connections detected.\n\n")
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

// Privilege escalation findings
	sb.WriteString("\n## Privilege Escalation Analysis\n\n")
	escalationCount := 0
	if len(data.Security) > 0 {
		sb.WriteString("| PID | Process | Privilege | Signed | Exe Path |\n")
		sb.WriteString("|---|---------|-----------|--------|----------|\n")
		var pids []int
		for pid := range data.Security {
			pids = append(pids, pid)
		}
		sort.Ints(pids)
		for _, pid := range pids {
			info := data.Security[pid]
			isElevated := info.PrivLevel == processinfo.Elevated || info.PrivLevel == processinfo.SYSTEM
			if isElevated && !info.IsSigned {
				sb.WriteString(fmt.Sprintf("| %d | `%s` | `%s` | %v | `%s` |\n",
					info.PID, info.Name, info.PrivLevel, info.IsSigned, info.ExePath))
				if info.IsPrivEscalation() {
					escalationCount++
				}
			}
		}
	}
	if escalationCount == 0 {
		sb.WriteString("No privilege escalation risks detected.\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n**%d process(es) with privilege escalation risk (elevated + unsigned + temp path)**\n\n", escalationCount))
	}

	// Baseline comparison
	sb.WriteString("\n## Baseline Comparison\n\n")
	if data.Baseline.BaselineAge > 0 || len(data.Baseline.New) > 0 || len(data.Baseline.Gone) > 0 {
		sb.WriteString(fmt.Sprintf("**Previous baseline age:** %s\n\n", data.Baseline.BaselineAge.Round(time.Second)))
		sb.WriteString(fmt.Sprintf("| Category | Count |\n"))
		sb.WriteString("|----------|-------|\n")
		sb.WriteString(fmt.Sprintf("| **New connections** | %d |\n", len(data.Baseline.New)))
		sb.WriteString(fmt.Sprintf("| **Disappeared** | %d |\n", len(data.Baseline.Gone)))
		sb.WriteString(fmt.Sprintf("| **Unchanged** | %d |\n", len(data.Baseline.Unchanged)))
		sb.WriteString("\n")

		if len(data.Baseline.New) > 0 {
			sb.WriteString("### New Connections\n\n")
			sb.WriteString("| Process | PID | DNS Name | Remote Address | Port | State |\n")
			sb.WriteString("|---------|---|----------|------|-----|-------|\n")
			for _, e := range data.Baseline.New {
				sb.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | `%s` | %d | `%s` |\n",
					e.Process, e.ProcessID, "", e.RemoteAddr, e.RemotePort, e.State))
			}
			sb.WriteString("\n")
		}

		if len(data.Baseline.Gone) > 0 {
			sb.WriteString("### Disappeared Connections\n\n")
			sb.WriteString("| Process | PID | DNS Name | Remote Address | Port | State |\n")
			sb.WriteString("|---------|---|----------|------|-----|-------|\n")
			for _, e := range data.Baseline.Gone {
				sb.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | `%s` | %d | `%s` |\n",
					e.Process, e.ProcessID, "", e.RemoteAddr, e.RemotePort, e.State))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("No previous baseline found. Run the scanner again to establish a comparison.\n\n")
	}

	// Findings summary
	findings := countFindings(data.Connections, data.Risks, escalationCount)
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
	sb.WriteString(fmt.Sprintf("| Privilege escalation risks | %d |\n", findings.PrivEscalationCount))
	sb.WriteString(fmt.Sprintf("| Whitelisted connections | %d |\n", findings.WhitelistedCount))

	return os.WriteFile(filename, []byte(sb.String()), 0644)
}

// IsExternal returns true if the connection goes to an external (non-private) IP.
func IsExternal(c scanner.Connection) bool {
	return scanner.IsExternalIP(c.RemoteAddr)
}

// IsSuspicious returns true if the connection target is outside the local machine.
func IsSuspicious(c scanner.Connection) bool {
	return !IsLocal(c.RemoteAddr)
}

// IsLocal returns true for loopback or private IP ranges (including IPv6).
func IsLocal(addr string) bool {
	return scanner.IsPrivateIP(addr)
}

// IsSuspiciousProcess checks whether the process name is one that warrants scrutiny.
func IsSuspiciousProcess(name string) bool {
	for n := range scanner.SuspiciousProcessNamesList() {
		if strings.ToLower(n) == strings.ToLower(name) {
			return true
		}
	}
	return false
}

func Summarize(data Data) Findings {
	privEscCount := 0
	for _, sec := range data.Security {
		isElevated := sec.PrivLevel == processinfo.Elevated || sec.PrivLevel == processinfo.SYSTEM
		if isElevated && !sec.IsSigned {
			privEscCount++
		}
	}
	return countFindings(data.Connections, data.Risks, privEscCount)
}

func countFindings(conns []scanner.Connection, risks []scanner.ConnectionRisk, privEscCount int) Findings {
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
	f.PrivEscalationCount = privEscCount

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
		if r.IsWhitelisted {
			f.WhitelistedCount++
		}
	}
	return f
}

func isSuspiciousPort(port int) bool {
	return scanner.IsSuspiciousPort(port)
}

// sanitizeMarkdown escapes pipe characters and backticks in strings used in Markdown tables.
func sanitizeMarkdown(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "`", "\\`")
}

// GenerateJSON writes the full scan data as a JSON file.
func GenerateJSON(data Data, filename string) error {
	type jsonReport struct {
		Version     string                    `json:"version"`
		ScanTime    string                    `json:"scan_time"`
		System      *systeminfo.SystemDetails `json:"system"`
		Connections []scanner.Connection      `json:"connections"`
		Processes   []scanner.ProcessEntry    `json:"processes"`
		Risks       []scanner.ConnectionRisk  `json:"risks"`
		Security    map[int]processinfo.Info  `json:"security"`
		Baseline    baseline.DiffResult       `json:"baseline"`
		Findings    Findings                  `json:"findings"`
		DNSLookups  int                       `json:"dns_lookups"`
	}

	dnsCount := 0
	for _, c := range data.Connections {
		if c.DNSName != "" {
			dnsCount++
		}
	}
	out := jsonReport{
		Version:     version.Version,
		ScanTime:    time.Now().Format(time.RFC3339),
		System:      data.System,
		Connections: data.Connections,
		Processes:   data.Processes,
		Risks:       data.Risks,
		Security:    data.Security,
		Baseline:    data.Baseline,
		Findings:    Summarize(data),
		DNSLookups:  dnsCount,
	}

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %w", err)
	}
	defer f.Close()

	enc2 := json.NewEncoder(f)
	enc2.SetIndent("", "  ")
	if err := enc2.Encode(out); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

// GenerateCSV writes connections and risks as CSV files.
func GenerateCSV(data Data, connectionsFile string, risksFile string) error {
	if err := writeConnectionsCSV(data.Connections, connectionsFile); err != nil {
		return err
	}
	if err := writeRisksCSV(data.Risks, risksFile); err != nil {
		return err
	}
	return nil
}

func writeConnectionsCSV(conns []scanner.Connection, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"ProcessID", "Process", "Executable", "LocalAddr", "LocalPort", "DNSName", "RemoteAddr", "RemotePort", "Protocol", "State", "Direction"}
	if err := w.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, c := range conns {
		record := []string{
			fmt.Sprintf("%d", c.ProcessID),
			c.Process,
			c.Executable,
			c.LocalAddr,
			fmt.Sprintf("%d", c.LocalPort),
			c.DNSName,
			c.RemoteAddr,
			fmt.Sprintf("%d", c.RemotePort),
			c.Protocol,
			c.State,
			c.Direction,
		}
		if err := w.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	return nil
}

func writeRisksCSV(risks []scanner.ConnectionRisk, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"RiskLevel", "ProcessID", "Process", "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort", "State", "Direction", "Reasons"}
	if err := w.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, r := range risks {
		record := []string{
			string(r.RiskLevel),
			fmt.Sprintf("%d", r.ProcessID),
			r.Process,
			r.LocalAddr,
			fmt.Sprintf("%d", r.LocalPort),
			r.RemoteAddr,
			fmt.Sprintf("%d", r.RemotePort),
			r.State,
			r.Direction,
			strings.Join(r.RiskReasons, "; "),
		}
		if err := w.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	return nil
}
