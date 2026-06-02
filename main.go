package main

import (
	"fmt"
	"log"
	"time"

	"networksentinel/report"
	"networksentinel/scanner"
	"networksentinel/systeminfo"
)

func main() {
	fmt.Println("=======================================")
	fmt.Println("  Process Network Analysis (Phase 1)")
	fmt.Println("=======================================")
	fmt.Println()

	// Gather system info
	fmt.Println("[1/4] Gathering system information...")
	sysInfo, err := systeminfo.Gather()
	if err != nil {
		log.Fatalf("Failed to gather system info: %v", err)
	}
	fmt.Printf("  Hostname: %s\n", sysInfo.Hostname)
	fmt.Printf("  OS: %s\n", sysInfo.OSPlatform)
	fmt.Printf("  Local IPs: %s\n", fmt.Sprintf("%v", sysInfo.LocalIPs))
	fmt.Println()

	// Scan connections and processes
	fmt.Println("[2/3] Scanning network connections and processes...")
	conns, procs, err := scanner.ScanAll()
	if err != nil {
		log.Fatalf("Failed to scan connections: %v", err)
	}
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
	fmt.Println("====================================")
	fmt.Println("  Risk Analysis")
	fmt.Println("====================================")
	risks := scanner.AssessConnectionRisk(conns)
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

	// Generate report
	fmt.Println("[3/4] Generating report...")
	reportData := report.Data{
		System:      sysInfo,
		Connections: conns,
		Processes:   procs,
		Risks:       risks,
	}
	filename := fmt.Sprintf("network_sentinel_%s_%s.md", sysInfo.Hostname, time.Now().Format("20060102_150405"))
	if err := report.GenerateMarkdown(reportData, filename); err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}
	fmt.Printf("  Report saved to: %s\n\n", filename)

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
