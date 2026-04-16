package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"networkscanner/report"
	"networkscanner/scanner"
	"networkscanner/systeminfo"
)

// runTUI is the main interactive function simulating the TUI experience.
func runTUI() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("============================================================")
	fmt.Println("         🚀 Advanced Network Intelligence Scanner")
	fmt.Println("============================================================")

	// --- 1. Get User Input ---
	fmt.Print("Enter Target CIDR (e.g., 192.168.1.0/24): ")
	cidr, _ := reader.ReadString('\n')
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		cidr = "127.0.0.1/32" // Default
	}

	var portStart int
	var portEnd int
	fmt.Print("Enter Start Port (e.g., 1): ")
	portStartStr, _ := reader.ReadString('\n')
	fmt.Sscan(strings.TrimSpace(portStartStr), &portStart)
	if portStart <= 0 {
		portStart = 1
	}

	fmt.Print("Enter End Port (e.g., 1024): ")
	portEndStr, _ := reader.ReadString('\n')
	fmt.Sscan(strings.TrimSpace(portEndStr), &portEnd)
	if portEnd <= 0 {
		portEnd = 10
	}

	var maxHosts int
	fmt.Print("Enter Max Hosts to scan (e.g., 256): ")
	maxHostsStr, _ := reader.ReadString('\n')
	fmt.Sscan(strings.TrimSpace(maxHostsStr), &maxHosts)
	if maxHosts <= 0 {
		maxHosts = 256
	}

	if cidr == "" || portStart == 0 || portEnd < portStart {
		fmt.Println("\n❌ Error: Invalid parameters. Exiting.")
		return
	}

	// --- 2. Gather System Information ---
	fmt.Println("\n[INFO] Gathering System Network Intelligence. This may take a moment...")
	sysInfo, err := systeminfo.GatherSystemInfo()
	if err != nil {
		log.Printf("⚠️ Warning: Failed to gather system info: %v. Proceeding with partial report.", err)
	} else {
		fmt.Println("✅ System info gathered successfully.")
	}

	// --- 3. Run Scan ---
	fmt.Printf("\n[INFO] Starting deep network scan on %s (Max: %d hosts) for ports %d-%d. This will take time...\n", cidr, maxHosts, portStart, portEnd)

	scanResults, err := scanner.RunScan(cidr, portStart, portEnd, maxHosts)

	if err != nil {
		fmt.Printf("\n⚠️ Warning: Scanning finished with error: %v\n", err)
	} else {
		fmt.Println("\n✅ Scanning complete. Analyzing results...")
	}

	// --- 4. Generate and Display Report ---
	reportData := report.ReportData{
		SystemInfo:  sysInfo,
		ScanResults: scanResults,
	}

	reportFileName := fmt.Sprintf("network_scan_report_%s.md", sysInfo.Hostname)

	fmt.Println("\n====================================================")
	fmt.Println("                ✨ SCAN REPORT ✨")
	fmt.Println("====================================================")

	consoleReport, readError := generateConsoleReport(reportData, cidr)
	if readError != nil {
		fmt.Printf("\n❌ Error generating console report: %v\n", readError)
		return
	}
	fmt.Println(consoleReport)

	if err := report.GenerateReport(reportData, reportFileName); err != nil {
		fmt.Printf("\n⚠️ Warning: Could not save full Markdown documentation to file: %v\n", err)
	} else {
		fmt.Printf("\n⭐ Intelligence Report also saved as: %s\n", reportFileName)
	}
}

func generateConsoleReport(data report.ReportData, cidr string) (string, error) {
	var sb strings.Builder

	sb.WriteString("================================================================\n")
	sb.WriteString("          🚀 ADVANCED NETWORK INTELLIGENCE SCAN REPORT         \n")
	sb.WriteString("================================================================\n")
	sb.WriteString(fmt.Sprintf("🗓️ Scan Time: %s\n", time.Now().Format(time.RFC1123)))
	sb.WriteString(fmt.Sprintf("🎯 Target Scope: %s\n", cidr))
	sb.WriteString(fmt.Sprintf("🔢 Port Range: 1 - 1024\n\n"))

	sb.WriteString("🌐 SYSTEM OVERVIEW:\n")
	sb.WriteString("-----------------\n")
	if data.SystemInfo != nil {
		sb.WriteString(fmt.Sprintf("   👤 Hostname: %s\n", data.SystemInfo.Hostname))
		sb.WriteString(fmt.Sprintf("   ⚙️ OS: %s\n", data.SystemInfo.OSPlatform))
		if len(data.SystemInfo.LocalIPs) > 0 {
			sb.WriteString(fmt.Sprintf("   💻 Local IPs: %s\n", strings.Join(data.SystemInfo.LocalIPs, ", ")))
		}
		if len(data.SystemInfo.MACAddresses) > 0 {
			sb.WriteString("   🔗 MAC Addresses: ")
			sb.WriteString(strings.Join(data.SystemInfo.MACAddresses, ", "))
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n🛡️ NETWORK INTELLIGENCE & ANOMALIES:\n")
	sb.WriteString("---------------------------\n")
	if data.SystemInfo != nil && len(data.SystemInfo.PotentialSpoof) > 0 {
		sb.WriteString("🚨 WARNING: POTENTIAL SPOOFING/VIRTUAL IPs DETECTED!\n")
		for _, ip := range data.SystemInfo.PotentialSpoof {
			sb.WriteString(fmt.Sprintf("  -> %s\n", ip))
		}
	} else {
		sb.WriteString("✅ No obvious spoofing/virtual IPs detected.\n")
	}

	sb.WriteString("\n🚪 SERVICE AND PORT SCAN RESULTS:\n")
	sb.WriteString("--------------------------------\n")
	if len(data.ScanResults) == 0 {
		sb.WriteString("No open ports found in the scanned range.\n")
	} else {
		for ip, ports := range data.ScanResults {
			sb.WriteString(fmt.Sprintf("  Host: %s\n", ip))
			for port, service := range ports {
				sb.WriteString(fmt.Sprintf("    -> Port %d: OPEN (%s)\n", port, service))
			}
		}
	}
	return sb.String(), nil
}

func main() {
	runTUI()
}
