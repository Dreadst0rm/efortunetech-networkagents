package main

import (
	"fmt"
	"log"
	"time"

	"networksentinel/baseline"
	"networksentinel/config"
	"networksentinel/report"
	"networksentinel/scanner"
	"networksentinel/systeminfo"
)

const baselineFile = "baseline.json"
const configFile = "config.json"

func main() {
	fmt.Println("=======================================")
	fmt.Println("  Process Network Analysis (Phase 1)")
	fmt.Println("=======================================")
	fmt.Println()

	// Load configuration
	cfg, err := config.Load(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	fmt.Printf("  IP conn threshold: %d | Process conn threshold: %d\n",
		cfg.Thresholds.MinIPConnections, cfg.Thresholds.MinProcessConnections)
	fmt.Printf("  Critical threshold: %d | High threshold: %d\n",
		cfg.Thresholds.CriticalThreshold, cfg.Thresholds.HighThreshold)
	fmt.Printf("  Excluded PIDs: %d | Excluded processes: %d\n",
		len(cfg.Excluded.PIDs), len(cfg.Excluded.Processes))
	fmt.Println()

	// Gather system info
	fmt.Println("[1/5] Gathering system information...")
	sysInfo, err := systeminfo.Gather()
	if err != nil {
		log.Fatalf("Failed to gather system info: %v", err)
	}
	fmt.Printf("  Hostname: %s\n", sysInfo.Hostname)
	fmt.Printf("  OS: %s\n", sysInfo.OSPlatform)
	fmt.Printf("  Local IPs: %s\n", fmt.Sprintf("%v", sysInfo.LocalIPs))
	fmt.Println()

	// Scan connections and processes
	fmt.Println("[2/5] Scanning network connections and processes...")
	conns, procs, secInfo, err := scanner.ScanAll(cfg)
	if err != nil {
		log.Fatalf("Failed to scan connections: %v", err)
	}
	fmt.Printf("  Security context gathered for %d processes\n", len(secInfo))
	fmt.Printf("  Found %d processes\n", len(procs))
	fmt.Printf("  Found %d network connections\n", len(conns))
	fmt.Println()

	// Summarize findings
	outboundCount := 0
	internalCount := 0
	suspiciousCount := 0
	for _, c := range conns {
		if c.Direction == "outbound" {
			outboundCount++
		} else {
			internalCount++
		}
		if report.IsSuspicious(c) {
			suspiciousCount++
		}
	}
	fmt.Printf("  Outbound connections: %d\n", outboundCount)
	fmt.Printf("  Internal connections: %d\n", internalCount)
	fmt.Printf("  Suspicious connections: %d\n", suspiciousCount)
	fmt.Println()

	// Risk analysis
	fmt.Println("[4/5] Analyzing connection risks...")
	fmt.Println("====================================")
	fmt.Println("  Risk Analysis")
	fmt.Println("====================================")
	risks := scanner.AssessConnectionRisk(conns, secInfo, cfg)
	critical, high, medium, low := 0, 0, 0, 0
	for _, r := range risks {
		switch r.RiskLevel {
		case scanner.RiskCritical:
			critical++
		case scanner.RiskHigh:
			high++
		case scanner.RiskMedium:
			medium++
		default:
			low++
		}
	}
	fmt.Printf("  Critical risk: %d | High risk: %d | Medium risk: %d | Low risk: %d\n", critical, high, medium, low)
	if len(risks) > 0 {
		fmt.Println()
		fmt.Println("  Top Risky Connections:")
		for i, r := range risks {
			if i >= 10 {
				break
			}
			fmt.Printf("    [%s] %s (PID: %d) -> %s:%d (%s)\n",
				r.RiskLevel, r.Process, r.ProcessID, r.RemoteAddr, r.RemotePort, r.State)
			for _, reason := range r.RiskReasons {
				fmt.Printf("      -> %s\n", reason)
			}
		}
		fmt.Println()
	}
	fmt.Println()

	// Baseline comparison
	var diff baseline.DiffResult
	prevSnap, err := baseline.Load(baselineFile)
	if err == nil && prevSnap != nil {
		fmt.Println("[3/5] Comparing against previous baseline...")
		currentEntries := make([]baseline.Entry, 0, len(conns))
		for _, c := range conns {
			currentEntries = append(currentEntries, baseline.Entry{
				ProcessID:  c.ProcessID,
				Process:    c.Process,
				LocalAddr:  c.LocalAddr,
				LocalPort:  c.LocalPort,
				RemoteAddr: c.RemoteAddr,
				RemotePort: c.RemotePort,
				State:      c.State,
			})
		}
		diff = baseline.Diff(currentEntries, prevSnap)
		fmt.Printf("  New connections: %d | Disappeared: %d | Unchanged: %d\n",
			len(diff.New), len(diff.Gone), len(diff.Unchanged))
		fmt.Printf("  Baseline age: %s\n", diff.BaselineAge.Round(time.Second))
		fmt.Println()
	} else {
		fmt.Println("[3/4] No previous baseline found (will create one after scan)")
		fmt.Println()
	}

	// Save current snapshot as new baseline
	currentEntries := make([]baseline.Entry, 0, len(conns))
	for _, c := range conns {
		currentEntries = append(currentEntries, baseline.Entry{
			ProcessID:  c.ProcessID,
			Process:    c.Process,
			LocalAddr:  c.LocalAddr,
			LocalPort:  c.LocalPort,
			RemoteAddr: c.RemoteAddr,
			RemotePort: c.RemotePort,
			State:      c.State,
		})
	}
	if err := baseline.Save(baselineFile, sysInfo.Hostname, currentEntries); err != nil {
		log.Printf("Warning: failed to save baseline: %v", err)
	}

	// Generate report
	fmt.Println("[5/5] Generating report...")
	reportData := report.Data{
		System:      sysInfo,
		Connections: conns,
		Processes:   procs,
		Risks:       risks,
		Security:    secInfo,
		Baseline:    diff,
	}
	timestamp := time.Now().Format("20060102_150405")
	mdFile := fmt.Sprintf("network_sentinel_%s_%s.md", sysInfo.Hostname, timestamp)
	if err := report.GenerateMarkdown(reportData, mdFile); err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}
	fmt.Printf("  Markdown: %s\n", mdFile)

	jsonFile := fmt.Sprintf("network_sentinel_%s_%s.json", sysInfo.Hostname, timestamp)
	if err := report.GenerateJSON(reportData, jsonFile); err != nil {
		log.Fatalf("Failed to generate JSON: %v", err)
	}
	fmt.Printf("  JSON:     %s\n", jsonFile)

	connCSV := fmt.Sprintf("network_sentinel_%s_%s_connections.csv", sysInfo.Hostname, timestamp)
	riskCSV := fmt.Sprintf("network_sentinel_%s_%s_risks.csv", sysInfo.Hostname, timestamp)
	if err := report.GenerateCSV(reportData, connCSV, riskCSV); err != nil {
		log.Fatalf("Failed to generate CSV: %v", err)
	}
	fmt.Printf("  CSV conns: %s\n", connCSV)
	fmt.Printf("  CSV risks: %s\n\n", riskCSV)

	// Print suspicious connections
	if suspiciousCount > 0 {
		fmt.Println("=======================================")
		fmt.Println("  Suspicious Connections")
		fmt.Println("=======================================")
		suspiciousConns := []scanner.Connection{}
		for _, c := range conns {
			if report.IsSuspicious(c) {
				suspiciousConns = append(suspiciousConns, c)
			}
		}
		for _, c := range suspiciousConns {
			isSuspProc := report.IsSuspiciousProcess(c.Process)
			flag := ""
			if isSuspProc {
				flag = " [SUSPICIOUS PROCESS]"
			}
			fmt.Printf("  PID: %d | Process: %s | %s:%d -> %s:%d (%s)%s\n",
				c.ProcessID, c.Process, c.LocalAddr, c.LocalPort,
				c.RemoteAddr, c.RemotePort, c.Protocol+":"+c.State, flag)
		}
		fmt.Println()
	}

	// Print top 10 processes by connection count
	fmt.Println("=======================================")
	fmt.Println("  Top Processes by Network Activity")
	fmt.Println("=======================================")
	procCount := make(map[string]int)
	procPID := make(map[string]int)
	for _, c := range conns {
		if c.Process != "" {
			procCount[c.Process]++
			procPID[c.Process] = c.ProcessID
		}
	}
	type procEntry struct {
		name  string
		count int
		pid   int
	}
	var sorted []procEntry
	for name, count := range procCount {
		sorted = append(sorted, procEntry{name, count, procPID[name]})
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for i, entry := range sorted {
		if i >= 10 {
			break
		}
		fmt.Printf("  %d. %s (PID: %d) - %d connections\n", i+1, entry.name, entry.pid, entry.count)
	}
	fmt.Println()
	fmt.Println("Analysis complete.")
}
