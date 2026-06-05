package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"networksentinel/alerting"
	"networksentinel/baseline"
	"networksentinel/config"
	"networksentinel/dns"
	"networksentinel/report"
	"networksentinel/scanner"
	"networksentinel/systeminfo"
	"networksentinel/threatintel"
	"networksentinel/version"
)

const baselineFile = "baseline.json"

var (
	configFile     = flag.String("config", "config.json", "Path to config file")
	outputDir      = flag.String("output", ".", "Output directory for reports")
	daemonInterval = flag.Int("daemon", 0, "Run in daemon mode with scan interval in seconds (0 = one-shot)")
	feedFile       = flag.String("feed", "", "Path to C2 threat intel JSON feed file")
	help           = flag.Bool("h", false, "Show help")
)

func main() {
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	fmt.Println("=======================================")
	fmt.Printf("  Process Network Analysis v%s\n", version.Version)
	fmt.Println("=======================================")
	fmt.Println()

	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	fmt.Printf("  IP conn threshold: %d | Process conn threshold: %d\n",
		cfg.Thresholds.MinIPConnections, cfg.Thresholds.MinProcessConnections)
	fmt.Printf("  Critical threshold: %d | High threshold: %d\n",
		cfg.Thresholds.CriticalThreshold, cfg.Thresholds.HighThreshold)
	fmt.Printf("  Excluded PIDs: %d | Excluded processes: %d\n",
		len(cfg.Excluded.PIDs), len(cfg.Excluded.Processes))
	fmt.Printf("  Whitelisted IPs: %d\n", len(cfg.Whitelist))
	fmt.Println()

	if *daemonInterval > 0 {
		runDaemon(cfg, *daemonInterval, *outputDir)
		return
	}

	runScan(cfg, *outputDir)
}

func runScan(cfg *config.Config, outputDir string) {
	fmt.Println("[1/5] Gathering system information...")
	sysInfo, err := systeminfo.Gather()
	if err != nil {
		log.Fatalf("Failed to gather system info: %v", err)
	}
	fmt.Printf("  Hostname: %s\n", sysInfo.Hostname)
	fmt.Printf("  OS: %s\n", sysInfo.OSPlatform)
	fmt.Printf("  Local IPs: %v\n", sysInfo.LocalIPs)
	fmt.Println()

	fmt.Println("[2/5] Scanning network connections and processes...")
	conns, procs, secInfo, err := scanner.ScanAll(cfg)
	if err != nil {
		log.Fatalf("Failed to scan connections: %v", err)
	}
	fmt.Printf("  Security context gathered for %d processes\n", len(secInfo))
	fmt.Printf("  Found %d processes\n", len(procs))
	fmt.Printf("  Found %d network connections\n", len(conns))

	// Perform DNS reverse lookup on outbound connections
	dnsCount := 0
	for i := range conns {
		c := &conns[i]
		if c.Direction == "outbound" && c.RemoteAddr != "" {
			dnsName := dns.LookupDomain(c.RemoteAddr)
			if dnsName != "" {
				c.DNSName = dnsName
				dnsCount++
			}
		}
	}
	if dnsCount > 0 {
		fmt.Printf("  DNS lookups resolved: %d\n", dnsCount)
	}
	fmt.Println()

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

	fmt.Println("[4/5] Analyzing connection risks...")
	fmt.Println("====================================")
	fmt.Println("  Risk Analysis")
	fmt.Println("====================================")

	// Load threat intelligence database
	tiDB := threatintel.NewThreatIntelDB()
	tiDB.AddIOCs(threatintel.KnownC2IPs)
	fmt.Printf("  Built-in threat intel: %d indicators\n", tiDB.Count())

	if *feedFile != "" {
		iocs, err := threatintel.GetFeedIOCs(*feedFile)
		if err != nil {
			log.Printf("Warning: failed to load feed %s: %v", *feedFile, err)
		} else {
			fmt.Printf("  + External feed %s: %d indicators\n", *feedFile, len(iocs))
			tiDB.AddIOCs(iocs)
			fmt.Printf("  Total threat intel: %d indicators\n", tiDB.Count())
		}
	}

	risks := scanner.AssessConnectionRiskWithThreatIntel(conns, secInfo, cfg, tiDB)
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

	// DNS query analysis
	if cfg.DNSLog {
		fmt.Println("[DNS] Capturing DNS queries...")

		// Capture DNS cache entries (platform-specific)
		captureResult, err := dns.CaptureDNSQueries(cfg, sysInfo.Hostname)
		if err != nil {
			log.Printf("Warning: DNS capture failed: %v", err)
		} else if captureResult != nil {
			fmt.Printf("  DNS queries captured: %d (method: %s)\n", len(captureResult.Queries), captureResult.CaptureMethod)

			// Also analyze connection remote addresses as potential DNS targets
			for _, c := range conns {
				if c.RemoteAddr != "" && c.RemoteAddr != "*" && c.RemoteAddr != "0.0.0.0" {
					result := dns.CheckDomain(c.RemoteAddr)
					if result.IsSuspicious {
						fmt.Printf("  Connection target suspicious: %s (confidence: %.2f) — %s\n", result.Domain, result.Confidence, result.Reason)
						captureResult.Queries = append(captureResult.Queries, dns.Query{
							PID:       c.ProcessID,
							Process:   c.Process,
							QueryName: c.RemoteAddr,
							Timestamp: time.Now(),
						})
					}
				}
			}

			// Save DNS capture to file
			dnsTimestamp := time.Now().Format("20060102_150405")
			dnsFile := fmt.Sprintf("%s/captured_dns_queries_%s_%s.json", outputDir, sysInfo.Hostname, dnsTimestamp)
			if err := dns.SaveCaptureResult(captureResult, dnsFile); err != nil {
				log.Printf("Warning: failed to save DNS capture: %v", err)
			} else {
				fmt.Printf("  DNS capture saved: %s\n", dnsFile)
			}
		}

		fmt.Println()
	}

	var diff baseline.DiffResult
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

	prevSnap, err := baseline.Load(baselineFile)
	if err == nil && prevSnap != nil {
		fmt.Println("[3/5] Comparing against previous baseline...")
		diff = baseline.Diff(currentEntries, prevSnap)
		fmt.Printf("  New connections: %d | Disappeared: %d | Unchanged: %d\n",
			len(diff.New), len(diff.Gone), len(diff.Unchanged))
		fmt.Printf("  Baseline age: %s\n", diff.BaselineAge.Round(time.Second))
		fmt.Println()
	} else {
		fmt.Println("[3/5] No previous baseline found (will create one after scan)")
		fmt.Println()
	}

	if err := baseline.Save(baselineFile, sysInfo.Hostname, currentEntries); err != nil {
		log.Printf("Warning: failed to save baseline: %v", err)
	}

	fmt.Println("[5/5] Generating report...")
	var whitelist []report.WhitelistedIP
	for _, w := range cfg.Whitelist {
		whitelist = append(whitelist, report.WhitelistedIP{
			IP:      w.IP,
			Comment: w.Comment,
		})
	}
	reportData := report.Data{
		System:      sysInfo,
		Connections: conns,
		Processes:   procs,
		Risks:       risks,
		Security:    secInfo,
		Baseline:    diff,
		Whitelist:   whitelist,
	}
	timestamp := time.Now().Format("20060102_150405")
	mdFile := fmt.Sprintf("%s/network_sentinel_%s_%s.md", outputDir, sysInfo.Hostname, timestamp)
	if err := report.GenerateMarkdown(reportData, mdFile); err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}
	fmt.Printf("  Markdown: %s\n", mdFile)

	jsonFile := fmt.Sprintf("%s/network_sentinel_%s_%s.json", outputDir, sysInfo.Hostname, timestamp)
	if err := report.GenerateJSON(reportData, jsonFile); err != nil {
		log.Fatalf("Failed to generate JSON: %v", err)
	}
	fmt.Printf("  JSON:     %s\n", jsonFile)

	connCSV := fmt.Sprintf("%s/network_sentinel_%s_%s_connections.csv", outputDir, sysInfo.Hostname, timestamp)
	riskCSV := fmt.Sprintf("%s/network_sentinel_%s_%s_risks.csv", outputDir, sysInfo.Hostname, timestamp)
	if err := report.GenerateCSV(reportData, connCSV, riskCSV); err != nil {
		log.Fatalf("Failed to generate CSV: %v", err)
	}
	fmt.Printf("  CSV conns: %s\n", connCSV)
	fmt.Printf("  CSV risks: %s\n\n", riskCSV)

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

	// Alerting
	if cfg.Alerting.Enabled {
		fmt.Println("[Alerting] Sending alerts...")
		reg := alerting.NewRegistry()
		if cfg.Alerting.WebhookURL != "" {
			reg.AddNotifier(&alerting.WebhookNotifier{URL: cfg.Alerting.WebhookURL})
		}
		reg.AddNotifier(&alerting.SyslogNotifier{})
		for _, r := range risks {
			if r.RiskLevel == scanner.RiskCritical || r.RiskLevel == scanner.RiskHigh {
				reg.Send(alerting.Alert{
					Timestamp: time.Now(),
					Level:     string(r.RiskLevel),
					Message:   fmt.Sprintf("%s (PID: %d) -> %s:%d", r.Process, r.ProcessID, r.RemoteAddr, r.RemotePort),
					Details:   strings.Join(r.RiskReasons, "; "),
				})
			}
		}
		fmt.Println()
	}

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
	var sorted []string
	for name := range procCount {
		sorted = append(sorted, name)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return procCount[sorted[i]] > procCount[sorted[j]]
	})
	for i, name := range sorted {
		if i >= 10 {
			break
		}
		fmt.Printf("  %d. %s (PID: %d) - %d connections\n", i+1, name, procPID[name], procCount[name])
	}
	fmt.Println()
	fmt.Println("Analysis complete.")
}

func runDaemon(cfg *config.Config, interval int, outputDir string) {
	fmt.Printf("Starting daemon mode (scan every %ds). Press Ctrl+C to stop.\n", interval)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fmt.Printf("\n[%s] Starting scheduled scan...\n", time.Now().Format("15:04:05"))
				runScan(cfg, outputDir)
			}
		}
	}()

	<-sigCh
	cancel()
	fmt.Println("\nShutting down daemon...")
	fmt.Println("Daemon stopped.")
}
