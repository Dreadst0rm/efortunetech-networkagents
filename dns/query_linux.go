//go:build linux

package dns

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"time"

	"networksentinel/config"
)

// CaptureDNSQueries collects DNS cache entries via journalctl on Linux.
func CaptureDNSQueries(cfg *config.Config, hostname string) (*CaptureResult, error) {
	if !cfg.DNSLog {
		return nil, nil
	}

	var queries []Query

	// Try journalctl first
	cmd := exec.Command("journalctl", "-u", "systemd-resolved", "--no-pager", "-n", "200", "--grep", "query")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			domain := extractDomainFromJournalLine(line)
			if domain != "" {
				queries = append(queries, Query{
					QueryName: domain,
					Timestamp: time.Now(),
				})
			}
		}
	}

	// Fallback: try /var/log/syslog
	if len(queries) == 0 {
		f, err := os.Open("/var/log/syslog")
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(strings.ToLower(line), "dns") || strings.Contains(strings.ToLower(line), "resolve") {
					domain := extractDomainFromLogLine(line)
					if domain != "" {
						queries = append(queries, Query{
							QueryName: domain,
							Timestamp: time.Now(),
						})
					}
				}
			}
		}
	}

	result := &CaptureResult{
		Timestamp:     time.Now(),
		Hostname:      hostname,
		Queries:       queries,
		CaptureMethod: "journalctl_or_syslog",
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

func extractDomainFromJournalLine(line string) string {
	parts := strings.Fields(line)
	for _, p := range parts {
		if strings.Contains(p, ".") && !strings.Contains(p, "=") {
			return p
		}
	}
	return ""
}

func extractDomainFromLogLine(line string) string {
	parts := strings.Fields(line)
	for _, p := range parts {
		if strings.Contains(p, ".") && !strings.Contains(p, "=") && len(p) > 3 {
			return p
		}
	}
	return ""
}