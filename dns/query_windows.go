//go:build windows

package dns

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"networksentinel/config"
)

// CaptureDNSQueries collects DNS cache entries via PowerShell WMI on Windows.
func CaptureDNSQueries(cfg *config.Config, hostname string) (*CaptureResult, error) {
	if !cfg.DNSLog {
		return nil, nil
	}

	script := `
		$entries = Get-CimInstance -ClassName MSFT_DNSClientCache -Namespace 'root\StandardActivityProvider' -ErrorAction SilentlyContinue
		if ($entries) {
			$entries | ForEach-Object {
				$json = $_ | Select-Object -Property Entry, TimeToLive, ProcessId | ConvertTo-Json -Compress
				Write-Output $json
			}
		}
	`

	cmd := exec.Command("powershell.exe", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return &CaptureResult{
			Timestamp:     time.Now(),
			Hostname:      hostname,
			CaptureMethod: "powershell_wmi_failed",
			Queries:       nil,
			Suspicious:    nil,
		}, nil
	}

	var queries []Query
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry struct {
			Entry      string `json:"Entry"`
			ProcessId  int    `json:"ProcessId"`
			TimeToLive int    `json:"TimeToLive"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Entry == "" {
			continue
		}
		queries = append(queries, Query{
			QueryName: entry.Entry,
			PID:       entry.ProcessId,
			Timestamp: time.Now(),
		})
	}

	result := &CaptureResult{
		Timestamp:     time.Now(),
		Hostname:      hostname,
		Queries:       queries,
		CaptureMethod: "powershell_wmi",
	}

	var suspicious []SuspiciousDomainResult
	for _, q := range queries {
		r := CheckDomain(q.QueryName)
		if r.IsSuspicious {
			suspicious = append(suspicious, r)
		}
	}
	result.Suspicious = suspicious

	return result, nil
}