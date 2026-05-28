package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"networkscanner/scanner"
	"networkscanner/systeminfo"
)

// ReportData aggregates all the data needed for the final readable report.
type ReportData struct {
	SystemInfo  *systeminfo.SystemDetails
	ScanResults scanner.ScanResult
	TargetCidr  string
	PortStart   int
	PortEnd     int
}

// GenerateReport takes the collected data and writes it to a Markdown file.
func GenerateReport(data ReportData, filename string) error {
	var sb strings.Builder

	// --- Title and Header ---
	sb.WriteString("# 💻 Network Intelligence Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("## 🗓️ Scan Details\n"))
	sb.WriteString(fmt.Sprintf("* **Scan Time:** %s*\n", time.Now().Format(time.RFC1123)))
	sb.WriteString(fmt.Sprintf("* **Target Scope:** %s\n", data.TargetCidr))
	sb.WriteString(fmt.Sprintf("* **Port Range:** %d - %d\n\n", data.PortStart, data.PortEnd))

	// --- System Information Section ---
	sb.WriteString("## 🌐 System Overview\n")
	sb.WriteString("This section reports static and dynamically gathered information about the host machine.\n\n")

	sb.WriteString("## 🖥️ Host Identification\n")
	sb.WriteString(fmt.Sprintf("* **Hostname:** %s\n", data.SystemInfo.Hostname))
	sb.WriteString(fmt.Sprintf("* **Operating System:** %s\n", data.SystemInfo.OSPlatform))
	if len(data.SystemInfo.LocalIPs) > 0 {
		sb.WriteString(fmt.Sprintf("* **Local IP Addresses Found:** `%s`\n\n", strings.Join(data.SystemInfo.LocalIPs, ", ")))
	}

	if len(data.SystemInfo.MACAddresses) > 0 {
		sb.WriteString("## 📡 MAC Addresses\n")
		sb.WriteString("The following MAC addresses were detected on the local interfaces:\n")
		for _, mac := range data.SystemInfo.MACAddresses {
			sb.WriteString(fmt.Sprintf("- `%s`\n", mac))
		}
		sb.WriteString("\n")
	}

	// --- Network Intelligence Section (Spoof/Virtual) ---
	sb.WriteString("## 🛡️ Network Intelligence & Anomalies\n")
	sb.WriteString("This section highlights potential network inconsistencies, including virtual or non-locally-bound IPs.\n")
	if len(data.SystemInfo.PotentialSpoof) > 0 {
		sb.WriteString("⚠️ **WARNING: POTENTIAL SPOOFING/VIRTUAL IPs DETECTED!** ⚠️\n")
		sb.WriteString("The following IP addresses in the target range are not directly bound to a local physical interface, suggesting they belong to a VM, VPN, or a potentially spoofed address.\n")
		for _, ip := range data.SystemInfo.PotentialSpoof {
			sb.WriteString(fmt.Sprintf("- `%s`\n", ip))
		}
	} else {
		sb.WriteString("✅ No obvious potential spoofing or virtual IPs detected in the scanned range.\n")
	}

	// --- Scanning Results Section ---
	sb.WriteString("\n## 🚪 Service and Port Scan Results\n")
	sb.WriteString("The table below details all open ports and the services running on those ports the scan could identify.\n\n")

	if len(data.ScanResults) == 0 {
		sb.WriteString("❌ **No Open Ports Found:** The scan did not detect any open ports in the specified range on monitored hosts.\n")
	} else {
		for ip, ports := range data.ScanResults {
			sb.WriteString(fmt.Sprintf("## 🟢 Host: `%s`\n", ip))
			sb.WriteString("| Port | Status | Discovered Service |\n")
			sb.WriteString("| :--- | :---: | :--- |\n")

			var sortedPorts []int
			for p := range ports {
				sortedPorts = append(sortedPorts, p)
			}
			sort.Ints(sortedPorts)

			for _, port := range sortedPorts {
				service := ports[port]
				sb.WriteString(fmt.Sprintf("| %d | 🟢 | %s |\n", port, service))
			}
			sb.WriteString("\n")
		}
	}

	// Write the content to the file (using current working directory for reliability)
	err := os.WriteFile(filename, []byte(sb.String()), 0644)
	if err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}
	return nil
}
