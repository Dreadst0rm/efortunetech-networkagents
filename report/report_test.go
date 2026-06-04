package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"networksentinel/baseline"
	"networksentinel/processinfo"
	"networksentinel/scanner"
	"networksentinel/systeminfo"
)

func TestSummarize(t *testing.T) {
	data := Data{
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443},
			{ProcessID: 2, Process: "cmd.exe", Direction: "outbound", RemoteAddr: "1.1.1.1", RemotePort: 4444},
			{ProcessID: 3, Process: "svchost.exe", Direction: "inbound", RemoteAddr: "0.0.0.0", RemotePort: 445},
		},
		Risks: []scanner.ConnectionRisk{
			{Connection: scanner.Connection{ProcessID: 2, Process: "cmd.exe", RemoteAddr: "1.1.1.1", RemotePort: 4444}, RiskLevel: scanner.RiskMedium, IsWhitelisted: false},
		},
		Security: map[int]processinfo.Info{
			2: {PID: 2, Name: "cmd.exe", PrivLevel: processinfo.Elevated, IsSigned: false},
		},
	}

	f := Summarize(data)
	if f.TotalOutbound != 2 {
		t.Errorf("TotalOutbound = %d, want 2", f.TotalOutbound)
	}
	if f.SuspiciousPorts != 1 {
		t.Errorf("SuspiciousPorts = %d, want 1", f.SuspiciousPorts)
	}
	if f.SuspiciousProcs != 1 {
		t.Errorf("SuspiciousProcs = %d, want 1", f.SuspiciousProcs)
	}
	if f.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", f.MediumCount)
	}
	if f.PrivEscalationCount != 1 {
		t.Errorf("PrivEscalationCount = %d, want 1", f.PrivEscalationCount)
	}
}

func TestSummarize_Empty(t *testing.T) {
	f := Summarize(Data{})
	if f.TotalOutbound != 0 {
		t.Errorf("TotalOutbound = %d, want 0", f.TotalOutbound)
	}
	if f.HighestRisk != "" {
		t.Errorf("HighestRisk = %q, want empty", f.HighestRisk)
	}
}

func TestSummarize_Whitelisted(t *testing.T) {
	data := Data{
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443},
		},
		Risks: []scanner.ConnectionRisk{
			{Connection: scanner.Connection{ProcessID: 1, Process: "chrome.exe", RemoteAddr: "8.8.8.8", RemotePort: 443}, RiskLevel: scanner.RiskMedium, IsWhitelisted: true},
		},
	}

	f := Summarize(data)
	if f.WhitelistedCount != 1 {
		t.Errorf("WhitelistedCount = %d, want 1", f.WhitelistedCount)
	}
}

func TestSummarize_HighestRisk(t *testing.T) {
	data := Data{
		Risks: []scanner.ConnectionRisk{
			{RiskLevel: scanner.RiskCritical},
			{RiskLevel: scanner.RiskMedium},
			{RiskLevel: scanner.RiskLow},
		},
	}

	f := Summarize(data)
	if f.HighestRisk == "" {
		t.Errorf("HighestRisk = %q, want non-empty (first risk)", f.HighestRisk)
	}
}

func TestGenerateJSON(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_report.json")

	data := Data{
		System: &systeminfo.SystemDetails{
			Hostname:   "testhost",
			OSPlatform: "windows",
			LocalIPs:   []string{"127.0.0.1"},
		},
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443, DNSName: "dns.google"},
		},
		Risks: []scanner.ConnectionRisk{
			{Connection: scanner.Connection{ProcessID: 1, Process: "chrome.exe", RemoteAddr: "8.8.8.8", RemotePort: 443}, RiskLevel: scanner.RiskLow},
		},
	}

	err := GenerateJSON(data, filename)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read JSON file: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(content, &raw); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	findings, ok := raw["findings"].(map[string]interface{})
	if !ok {
		t.Fatal("findings not found in JSON")
	}

	if findings["TotalOutbound"] != float64(1) {
		t.Errorf("TotalOutbound = %v, want 1", findings["TotalOutbound"])
	}

	dnsLookups, ok := raw["dns_lookups"].(float64)
	if !ok {
		t.Fatal("dns_lookups not found in JSON")
	}
	if dnsLookups != 1 {
		t.Errorf("dns_lookups = %v, want 1", dnsLookups)
	}
}

func TestGenerateJSON_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "empty.json")

	data := Data{
		System: &systeminfo.SystemDetails{
			Hostname:   "empty",
			OSPlatform: "linux",
		},
	}

	err := GenerateJSON(data, filename)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read JSON: %v", err)
	}
	if !strings.Contains(string(content), `"connections": null`) && !strings.Contains(string(content), `"connections":[]`) {
		t.Error("expected empty or null connections in JSON")
	}
}

func TestGenerateCSV(t *testing.T) {
	tmpDir := t.TempDir()
	connFile := filepath.Join(tmpDir, "connections.csv")
	risksFile := filepath.Join(tmpDir, "risks.csv")

	data := Data{
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443, DNSName: "dns.google"},
			{ProcessID: 2, Process: "cmd.exe", Direction: "outbound", RemoteAddr: "1.1.1.1", RemotePort: 4444},
		},
		Risks: []scanner.ConnectionRisk{
			{Connection: scanner.Connection{ProcessID: 2, Process: "cmd.exe", RemoteAddr: "1.1.1.1", RemotePort: 4444}, RiskLevel: scanner.RiskMedium, RiskReasons: []string{"suspicious port 4444"}},
		},
	}

	err := GenerateCSV(data, connFile, risksFile)
	if err != nil {
		t.Fatalf("GenerateCSV failed: %v", err)
	}

	connContent, err := os.ReadFile(connFile)
	if err != nil {
		t.Fatalf("Failed to read connections CSV: %v", err)
	}
	if !strings.Contains(string(connContent), "DNSName") {
		t.Error("CSV header missing DNSName column")
	}
	if !strings.Contains(string(connContent), "dns.google") {
		t.Error("CSV missing DNS name data")
	}

	risksContent, err := os.ReadFile(risksFile)
	if err != nil {
		t.Fatalf("Failed to read risks CSV: %v", err)
	}
	if !strings.Contains(string(risksContent), "medium") {
		t.Error("risks CSV missing risk level")
	}
	if !strings.Contains(string(risksContent), "suspicious port 4444") {
		t.Error("risks CSV missing risk reasons")
	}
}

func TestGenerateCSV_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	connFile := filepath.Join(tmpDir, "empty_conn.csv")
	risksFile := filepath.Join(tmpDir, "empty_risks.csv")

	data := Data{}

	err := GenerateCSV(data, connFile, risksFile)
	if err != nil {
		t.Fatalf("GenerateCSV failed: %v", err)
	}

	connContent, err := os.ReadFile(connFile)
	if err != nil {
		t.Fatalf("Failed to read connections CSV: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(connContent)), "\n")
	if len(lines) != 1 {
		t.Errorf("connections CSV should have only header line, got %d lines", len(lines))
	}
}

func TestWriteConnectionsCSV_Header(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "header_test.csv")

	err := writeConnectionsCSV(nil, filename)
	if err != nil {
		t.Fatalf("writeConnectionsCSV failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}
	header := string(content)
	expectedCols := []string{"ProcessID", "Process", "Executable", "DNSName", "RemoteAddr", "RemotePort"}
	for _, col := range expectedCols {
		if !strings.Contains(header, col) {
			t.Errorf("CSV header missing column: %s", col)
		}
	}
}

func TestWriteRisksCSV_Header(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "risks_header.csv")

	err := writeRisksCSV(nil, filename)
	if err != nil {
		t.Fatalf("writeRisksCSV failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}
	header := string(content)
	expectedCols := []string{"RiskLevel", "ProcessID", "Process", "RemoteAddr", "Reasons"}
	for _, col := range expectedCols {
		if !strings.Contains(header, col) {
			t.Errorf("CSV header missing column: %s", col)
		}
	}
}

func TestGenerateMarkdown_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test.md")

	data := Data{
		System: &systeminfo.SystemDetails{
			Hostname:   "testhost",
			OSPlatform: "windows",
			LocalIPs:   []string{"127.0.0.1"},
		},
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443, DNSName: "dns.google"},
		},
		Risks: []scanner.ConnectionRisk{},
	}

	err := GenerateMarkdown(data, filename)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read markdown: %v", err)
	}

	if !strings.Contains(string(content), "testhost") {
		t.Error("Markdown missing hostname")
	}
	if !strings.Contains(string(content), "## System Information") {
		t.Error("Markdown missing system info section")
	}
	if !strings.Contains(string(content), "## Network Connections Summary") {
		t.Error("Markdown missing connections summary section")
	}
	if !strings.Contains(string(content), "## Key Findings") {
		t.Error("Markdown missing key findings section")
	}
}

func TestGenerateMarkdown_NoRisks(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "no_risks.md")

	data := Data{
		System: &systeminfo.SystemDetails{
			Hostname:   "clean",
			OSPlatform: "linux",
		},
		Connections: []scanner.Connection{},
		Risks:       []scanner.ConnectionRisk{},
	}

	err := GenerateMarkdown(data, filename)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read markdown: %v", err)
	}

	if !strings.Contains(string(content), "No suspicious connections found") {
		t.Error("Markdown should indicate no suspicious connections")
	}
}

func TestGenerateJSON_DNSCount(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "dns_count.json")

	data := Data{
		System: &systeminfo.SystemDetails{
			Hostname:   "dns-test",
			OSPlatform: "windows",
		},
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443, DNSName: "dns.google"},
			{ProcessID: 2, Process: "cmd.exe", Direction: "outbound", RemoteAddr: "1.1.1.1", RemotePort: 443},
			{ProcessID: 3, Process: "svchost.exe", Direction: "outbound", RemoteAddr: "1.0.0.1", RemotePort: 443, DNSName: "one.one.one.one"},
		},
	}

	err := GenerateJSON(data, filename)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read JSON: %v", err)
	}

	var raw map[string]interface{}
	json.Unmarshal(content, &raw)

	dnsLookups := raw["dns_lookups"].(float64)
	if dnsLookups != 2 {
		t.Errorf("dns_lookups = %v, want 2", dnsLookups)
	}
}

func TestGenerateCSV_RisksWithWhitelisted(t *testing.T) {
	tmpDir := t.TempDir()
	connFile := filepath.Join(tmpDir, "wl_conn.csv")
	risksFile := filepath.Join(tmpDir, "wl_risks.csv")

	data := Data{
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443},
		},
		Risks: []scanner.ConnectionRisk{
			{Connection: scanner.Connection{ProcessID: 1, Process: "chrome.exe", RemoteAddr: "8.8.8.8", RemotePort: 443}, RiskLevel: scanner.RiskMedium, IsWhitelisted: true, RiskReasons: []string{"suspicious port 443"}},
		},
	}

	err := GenerateCSV(data, connFile, risksFile)
	if err != nil {
		t.Fatalf("GenerateCSV failed: %v", err)
	}

	risksContent, err := os.ReadFile(risksFile)
	if err != nil {
		t.Fatalf("Failed to read risks CSV: %v", err)
	}
	if !strings.Contains(string(risksContent), "medium") {
		t.Error("risks CSV should contain medium risk level")
	}
}

func TestGenerateMarkdown_WhitelistedSection(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "wl.md")

	data := Data{
		System: &systeminfo.SystemDetails{
			Hostname:   "wl-test",
			OSPlatform: "windows",
		},
		Connections: []scanner.Connection{},
		Risks: []scanner.ConnectionRisk{
			{
				Connection: scanner.Connection{ProcessID: 1, Process: "chrome.exe", RemoteAddr: "8.8.8.8", RemotePort: 443, DNSName: "dns.google"},
				RiskLevel:  scanner.RiskMedium,
				IsWhitelisted: true,
				RiskReasons: []string{"suspicious port 443"},
			},
		},
		Whitelist: []WhitelistedIP{
			{IP: "8.8.8.8", Comment: "Google DNS"},
		},
	}

	err := GenerateMarkdown(data, filename)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read markdown: %v", err)
	}

	if !strings.Contains(string(content), "## Whitelisted Connections") {
		t.Error("Markdown should have Whitelisted Connections section")
	}
	if !strings.Contains(string(content), "Google DNS") {
		t.Error("Markdown should show whitelist comment")
	}
}

func TestGenerateMarkdown_WhitelistedNoRisks(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "wl_no_risks.md")

	data := Data{
		System:      &systeminfo.SystemDetails{Hostname: "test", OSPlatform: "linux"},
		Connections: []scanner.Connection{},
		Risks:       []scanner.ConnectionRisk{},
		Whitelist:   []WhitelistedIP{{IP: "8.8.8.8", Comment: "Google DNS"}},
	}

	err := GenerateMarkdown(data, filename)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read markdown: %v", err)
	}

	if !strings.Contains(string(content), "No whitelisted connections detected") {
		t.Error("Markdown should indicate no whitelisted connections when there are no risks")
	}
}

func TestSummarize_CountFindings(t *testing.T) {
	conns := []scanner.Connection{
		{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443},
		{ProcessID: 2, Process: "cmd.exe", Direction: "outbound", RemoteAddr: "1.1.1.1", RemotePort: 4444},
		{ProcessID: 3, Process: "svchost.exe", Direction: "inbound", RemoteAddr: "0.0.0.0", RemotePort: 445},
	}
	risks := []scanner.ConnectionRisk{
		{Connection: scanner.Connection{ProcessID: 2, Process: "cmd.exe", RemoteAddr: "1.1.1.1", RemotePort: 4444}, RiskLevel: scanner.RiskHigh},
		{Connection: scanner.Connection{ProcessID: 4, Process: "powershell.exe", RemoteAddr: "2.2.2.2", RemotePort: 443}, RiskLevel: scanner.RiskCritical},
	}

	f := countFindings(conns, risks, 0)
	if f.TotalOutbound != 2 {
		t.Errorf("TotalOutbound = %d, want 2", f.TotalOutbound)
	}
	if f.ExternalEndpoints != 2 {
		t.Errorf("ExternalEndpoints = %d, want 2", f.ExternalEndpoints)
	}
	if f.SuspiciousPorts != 1 {
		t.Errorf("SuspiciousPorts = %d, want 1", f.SuspiciousPorts)
	}
	if f.SuspiciousProcs != 1 {
		t.Errorf("SuspiciousProcs = %d, want 1", f.SuspiciousProcs)
	}
	if f.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", f.CriticalCount)
	}
	if f.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", f.HighCount)
	}
	if f.HighestRisk == "" {
		t.Errorf("HighestRisk = %q, want non-empty (first risk)", f.HighestRisk)
	}
}

func TestSummarize_Baseline(t *testing.T) {
	data := Data{
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443},
		},
		Risks: []scanner.ConnectionRisk{},
		Baseline: baseline.DiffResult{
			New: []baseline.Entry{
				{ProcessID: 1, Process: "chrome.exe", RemoteAddr: "8.8.8.8", RemotePort: 443},
			},
			Gone: []baseline.Entry{
				{ProcessID: 2, Process: "cmd.exe", RemoteAddr: "1.1.1.1", RemotePort: 443},
			},
			Unchanged: []baseline.Entry{
				{ProcessID: 3, Process: "svchost.exe", RemoteAddr: "10.0.0.1", RemotePort: 445},
			},
			BaselineAge: 0,
		},
	}

	err := GenerateMarkdown(data, filepath.Join(t.TempDir(), "baseline.md"))
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	f := Summarize(data)
	if f.TotalOutbound != 1 {
		t.Errorf("TotalOutbound = %d, want 1", f.TotalOutbound)
	}
}

func TestGenerateJSON_WhitelistedCount(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "wl_count.json")

	data := Data{
		System: &systeminfo.SystemDetails{
			Hostname:   "wl-count",
			OSPlatform: "windows",
		},
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443},
		},
		Risks: []scanner.ConnectionRisk{
			{Connection: scanner.Connection{ProcessID: 1, Process: "chrome.exe", RemoteAddr: "8.8.8.8", RemotePort: 443}, RiskLevel: scanner.RiskMedium, IsWhitelisted: true},
			{Connection: scanner.Connection{ProcessID: 2, Process: "cmd.exe", RemoteAddr: "1.1.1.1", RemotePort: 4444}, RiskLevel: scanner.RiskHigh, IsWhitelisted: false},
		},
	}

	err := GenerateJSON(data, filename)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read JSON: %v", err)
	}

	var raw map[string]interface{}
	json.Unmarshal(content, &raw)

	findings := raw["findings"].(map[string]interface{})
	whitelisted := findings["WhitelistedCount"].(float64)
	if whitelisted != 1 {
		t.Errorf("WhitelistedCount = %v, want 1", whitelisted)
	}
}

func TestSummarize_NoOutbound(t *testing.T) {
	data := Data{
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "svchost.exe", Direction: "inbound", RemoteAddr: "0.0.0.0", RemotePort: 445},
		},
	}

	f := Summarize(data)
	if f.TotalOutbound != 0 {
		t.Errorf("TotalOutbound = %d, want 0", f.TotalOutbound)
	}
}

func TestGenerateMarkdown_ConnStateSummary(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "conn_state.md")

	data := Data{
		System: &systeminfo.SystemDetails{
			Hostname:   "state-test",
			OSPlatform: "windows",
		},
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", State: "ESTABLISHED", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443},
			{ProcessID: 2, Process: "cmd.exe", State: "CLOSE_WAIT", Direction: "outbound", RemoteAddr: "1.1.1.1", RemotePort: 443},
			{ProcessID: 3, Process: "svchost.exe", State: "LISTENING", Direction: "inbound", RemoteAddr: "0.0.0.0", RemotePort: 445},
		},
	}

	err := GenerateMarkdown(data, filename)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read markdown: %v", err)
	}

	if !strings.Contains(string(content), "ESTABLISHED") {
		t.Error("Markdown should contain ESTABLISHED state")
	}
	if !strings.Contains(string(content), "CLOSE_WAIT") {
		t.Error("Markdown should contain CLOSE_WAIT state")
	}
	if !strings.Contains(string(content), "LISTENING") {
		t.Error("Markdown should contain LISTENING state")
	}
}

func TestGenerateMarkdown_NewConnectionsSection(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "new_conn.md")

	data := Data{
		System:      &systeminfo.SystemDetails{Hostname: "test", OSPlatform: "linux"},
		Connections: []scanner.Connection{},
		Risks:       []scanner.ConnectionRisk{},
		Baseline: baseline.DiffResult{
			New: []baseline.Entry{
				{ProcessID: 1, Process: "chrome.exe", RemoteAddr: "8.8.8.8", RemotePort: 443, State: "ESTABLISHED"},
			},
		},
	}

	err := GenerateMarkdown(data, filename)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read markdown: %v", err)
	}

	if !strings.Contains(string(content), "### New Connections") {
		t.Error("Markdown should have New Connections subsection")
	}
}

func TestGenerateMarkdown_DisappearedSection(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "gone_conn.md")

	data := Data{
		System:      &systeminfo.SystemDetails{Hostname: "test", OSPlatform: "linux"},
		Connections: []scanner.Connection{},
		Risks:       []scanner.ConnectionRisk{},
		Baseline: baseline.DiffResult{
			Gone: []baseline.Entry{
				{ProcessID: 2, Process: "cmd.exe", RemoteAddr: "1.1.1.1", RemotePort: 443, State: "ESTABLISHED"},
			},
		},
	}

	err := GenerateMarkdown(data, filename)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read markdown: %v", err)
	}

	if !strings.Contains(string(content), "### Disappeared Connections") {
		t.Error("Markdown should have Disappeared Connections subsection")
	}
}

func TestSanitizeMarkdown(t *testing.T) {
	if got := sanitizeMarkdown("hello | world"); got != "hello \\| world" {
		t.Errorf("sanitizeMarkdown('hello | world') = %q, want 'hello \\| world'", got)
	}
	if got := sanitizeMarkdown("use `code`"); got != "use \\`code\\`" {
		t.Errorf("sanitizeMarkdown('use `code`') = %q, want 'use \\`code\\`'", got)
	}
	if got := sanitizeMarkdown("normal text"); got != "normal text" {
		t.Errorf("sanitizeMarkdown('normal text') = %q, want 'normal text'", got)
	}
}

func TestGenerateMarkdown_WhitelistedWithSpecialChars(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "special.md")

	data := Data{
		System: &systeminfo.SystemDetails{Hostname: "test", OSPlatform: "linux"},
		Connections: []scanner.Connection{},
		Risks: []scanner.ConnectionRisk{
			{
				Connection:    scanner.Connection{ProcessID: 1, Process: "chrome.exe", RemoteAddr: "8.8.8.8", RemotePort: 443},
				RiskLevel:     scanner.RiskMedium,
				IsWhitelisted: true,
			},
		},
		Whitelist: []WhitelistedIP{
			{IP: "8.8.8.8", Comment: "Google | DNS `test`"},
		},
	}

	err := GenerateMarkdown(data, filename)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read markdown: %v", err)
	}

	if !strings.Contains(string(content), `Google \| DNS \`) {
		t.Error("Markdown should escape pipe and backtick in whitelist comment")
	}
}

func TestGenerateMarkdown_NoBaselineFound(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "no_baseline.md")

	data := Data{
		System:      &systeminfo.SystemDetails{Hostname: "test", OSPlatform: "linux"},
		Connections: []scanner.Connection{},
		Risks:       []scanner.ConnectionRisk{},
	}

	err := GenerateMarkdown(data, filename)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read markdown: %v", err)
	}

	if !strings.Contains(string(content), "No previous baseline found") {
		t.Error("Markdown should indicate no baseline found")
	}
}

func TestGenerateCSV_RisksWithMultipleReasons(t *testing.T) {
	tmpDir := t.TempDir()
	connFile := filepath.Join(tmpDir, "multi_reason_conn.csv")
	risksFile := filepath.Join(tmpDir, "multi_reason_risks.csv")

	data := Data{
		Connections: []scanner.Connection{},
		Risks: []scanner.ConnectionRisk{
			{
				Connection:    scanner.Connection{ProcessID: 1, Process: "cmd.exe", RemoteAddr: "1.1.1.1", RemotePort: 4444},
				RiskLevel:     scanner.RiskCritical,
				RiskReasons:   []string{"suspicious port 4444", "suspicious process: cmd.exe", "connection state: SYN_SENT"},
				IsWhitelisted: false,
			},
		},
	}

	err := GenerateCSV(data, connFile, risksFile)
	if err != nil {
		t.Fatalf("GenerateCSV failed: %v", err)
	}

	risksContent, err := os.ReadFile(risksFile)
	if err != nil {
		t.Fatalf("Failed to read risks CSV: %v", err)
	}

	if !strings.Contains(string(risksContent), "suspicious port 4444") {
		t.Error("risks CSV should contain first reason")
	}
	if !strings.Contains(string(risksContent), "suspicious process: cmd.exe") {
		t.Error("risks CSV should contain second reason")
	}
	if !strings.Contains(string(risksContent), "connection state: SYN_SENT") {
		t.Error("risks CSV should contain third reason")
	}
}

func TestGenerateCSV_ConnectionsWithDNSName(t *testing.T) {
	tmpDir := t.TempDir()
	connFile := filepath.Join(tmpDir, "dns_conn.csv")
	risksFile := filepath.Join(tmpDir, "dns_risks.csv")

	data := Data{
		Connections: []scanner.Connection{
			{ProcessID: 1, Process: "chrome.exe", Direction: "outbound", RemoteAddr: "8.8.8.8", RemotePort: 443, DNSName: "dns.google"},
			{ProcessID: 2, Process: "cmd.exe", Direction: "outbound", RemoteAddr: "1.1.1.1", RemotePort: 443},
		},
		Risks: []scanner.ConnectionRisk{},
	}

	err := GenerateCSV(data, connFile, risksFile)
	if err != nil {
		t.Fatalf("GenerateCSV failed: %v", err)
	}

	connContent, err := os.ReadFile(connFile)
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(connContent)), "\n")
	if len(lines) < 3 {
		t.Fatalf("CSV should have header + 2 data rows, got %d lines", len(lines))
	}

	// Second row should have dns.google in DNSName column
	if !strings.Contains(lines[1], "dns.google") {
		t.Error("First data row should contain dns.google")
	}
	// Third row should have empty DNSName
	if !strings.Contains(lines[2], "1.1.1.1") {
		t.Error("Second data row should contain 1.1.1.1")
	}
}
