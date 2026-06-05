//go:build darwin

package dns

import (
	"bufio"
	"os/exec"
	"strings"
	"time"

	"networksentinel/config"
)

// CaptureDNSQueries collects DNS cache entries via dscacheutil and log on macOS.
// Falls back to miekg/dns forward lookups when platform capture yields nothing.
func CaptureDNSQueries(cfg *config.Config, hostname string) (*CaptureResult, error) {
	if !cfg.DNSLog {
		return nil, nil
	}

	var queries []Query

	// Try dscacheutil first
	cmd := exec.Command("dscacheutil", "-q", "host", "-a", "name")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "name:") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain := parts[0]
				queries = append(queries, Query{
					QueryName: domain,
					Timestamp: time.Now(),
				})
			}
		}
	}

	// Fallback: try system log
	if len(queries) == 0 {
		cmd2 := exec.Command("log", "show", "--style", "raw", "--predicate", "eventMessage CONTAINS 'DNS'", "--last", "1h")
		output2, err2 := cmd2.Output()
		if err2 == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(output2)))
			for scanner.Scan() {
				line := scanner.Text()
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

	// miekg/dns fallback: resolve connection remote addresses via PTR
	if len(queries) == 0 {
		queries = resolveConnectionDomains(nil)
	}

	result := &CaptureResult{
		Timestamp:     time.Now(),
		Hostname:      hostname,
		Queries:       queries,
		CaptureMethod: "dscacheutil_or_log",
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

func extractDomainFromLogLine(line string) string {
	parts := strings.Fields(line)
	for _, p := range parts {
		if strings.Contains(p, ".") && !strings.Contains(p, "=") && len(p) > 3 {
			return p
		}
	}
	return ""
}
