package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Thresholds.MinIPConnections != 5 {
		t.Errorf("expected MinIPConnections=5, got %d", cfg.Thresholds.MinIPConnections)
	}
	if cfg.Thresholds.MinProcessConnections != 5 {
		t.Errorf("expected MinProcessConnections=5, got %d", cfg.Thresholds.MinProcessConnections)
	}
	if cfg.Thresholds.CriticalThreshold != 3 {
		t.Errorf("expected CriticalThreshold=3, got %d", cfg.Thresholds.CriticalThreshold)
	}
	if cfg.Thresholds.HighThreshold != 2 {
		t.Errorf("expected HighThreshold=2, got %d", cfg.Thresholds.HighThreshold)
	}
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load("__nonexistent_config__.json")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	expected := Defaults()
	if cfg.Thresholds.MinIPConnections != expected.Thresholds.MinIPConnections {
		t.Errorf("expected defaults, got MinIPConnections=%d", cfg.Thresholds.MinIPConnections)
	}
}

func TestLoadValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_config.json")
	data := []byte(`{
		"thresholds": {
			"min_ip_connections": 10,
			"min_process_connections": 20,
			"critical_threshold": 5,
			"high_threshold": 3
		},
		"excluded": {
			"pids": [1, 2],
			"processes": ["svchost.exe"]
		}
	}`)
	if err := os.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(filename)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cfg.Thresholds.MinIPConnections != 10 {
		t.Errorf("expected MinIPConnections=10, got %d", cfg.Thresholds.MinIPConnections)
	}
	if cfg.Thresholds.MinProcessConnections != 20 {
		t.Errorf("expected MinProcessConnections=20, got %d", cfg.Thresholds.MinProcessConnections)
	}
	if len(cfg.Excluded.PIDs) != 2 {
		t.Errorf("expected 2 excluded PIDs, got %d", len(cfg.Excluded.PIDs))
	}
	if len(cfg.Excluded.Processes) != 1 {
		t.Errorf("expected 1 excluded process, got %d", len(cfg.Excluded.Processes))
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(filename, []byte("{invalid}"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	_, err := Load(filename)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestIsExcludedPID(t *testing.T) {
	cfg := &Config{
		Excluded: Excluded{
			PIDs: []int{100, 200, 300},
		},
	}
	if !cfg.IsExcludedPID(200) {
		t.Error("expected PID 200 to be excluded")
	}
	if cfg.IsExcludedPID(999) {
		t.Error("expected PID 999 to NOT be excluded")
	}
}

func TestIsExcludedProcess(t *testing.T) {
	cfg := &Config{
		Excluded: Excluded{
			Processes: []string{"chrome.exe", "firefox.exe"},
		},
	}
	if !cfg.IsExcludedProcess("chrome.exe") {
		t.Error("expected chrome.exe to be excluded")
	}
	if cfg.IsExcludedProcess("notepad.exe") {
		t.Error("expected notepad.exe to NOT be excluded")
	}
}

func TestThresholdValidation_CriticalMustNotBeLowerThanHigh(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_config.json")
	data := []byte(`{
		"thresholds": {
			"min_ip_connections": 5,
			"min_process_connections": 5,
			"critical_threshold": 1,
			"high_threshold": 5
		}
	}`)
	if err := os.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(filename)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cfg.Thresholds.CriticalThreshold < cfg.Thresholds.HighThreshold {
		t.Errorf("expected CriticalThreshold >= HighThreshold, got Critical=%d High=%d", cfg.Thresholds.CriticalThreshold, cfg.Thresholds.HighThreshold)
	}
}

func TestWhitelistDefaults(t *testing.T) {
	cfg := Defaults()
	if len(cfg.Whitelist) != 0 {
		t.Errorf("expected empty whitelist, got %d entries", len(cfg.Whitelist))
	}
}

func TestIsWhitelistedIP(t *testing.T) {
	cfg := &Config{
		Whitelist: []WhitelistedIP{
			{IP: "8.8.8.8", Comment: "Google DNS"},
			{IP: "1.1.1.1", Comment: "Cloudflare DNS"},
		},
	}
	if !cfg.IsWhitelistedIP("8.8.8.8") {
		t.Error("expected 8.8.8.8 to be whitelisted")
	}
	if cfg.IsWhitelistedIP("8.8.4.4") {
		t.Error("expected 8.8.4.4 to NOT be whitelisted (different IP)")
	}
	if cfg.IsWhitelistedIP("1.2.3.4") {
		t.Error("expected 1.2.3.4 to NOT be whitelisted")
	}
	if cfg.IsWhitelistedIP("8.8.8.9") {
		t.Error("expected 8.8.8.9 to NOT be whitelisted")
	}
}

func TestIsWhitelistedIPCaseInsensitive(t *testing.T) {
	cfg := &Config{
		Whitelist: []WhitelistedIP{
			{IP: "8.8.8.8", Comment: "Google DNS"},
		},
	}
	if !cfg.IsWhitelistedIP("8.8.8.8") {
		t.Error("expected 8.8.8.8 to match")
	}
}

func TestGetWhitelistComment(t *testing.T) {
	cfg := &Config{
		Whitelist: []WhitelistedIP{
			{IP: "8.8.8.8", Comment: "Google DNS Primary"},
			{IP: "1.1.1.1", Comment: "Cloudflare DNS"},
		},
	}
	if got := cfg.GetWhitelistComment("8.8.8.8"); got != "Google DNS Primary" {
		t.Errorf("expected 'Google DNS Primary', got '%s'", got)
	}
	if got := cfg.GetWhitelistComment("1.1.1.1"); got != "Cloudflare DNS" {
		t.Errorf("expected 'Cloudflare DNS', got '%s'", got)
	}
	if got := cfg.GetWhitelistComment("1.2.3.4"); got != "" {
		t.Errorf("expected empty string for non-whitelisted IP, got '%s'", got)
	}
}

func TestLoadWithWhitelist(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_config.json")
	data := []byte(`{
		"thresholds": {
			"min_ip_connections": 3,
			"min_process_connections": 3,
			"critical_threshold": 2,
			"high_threshold": 2
		},
		"whitelist": [
			{"ip": "8.8.8.8", "comment": "Google DNS"},
			{"ip": "1.1.1.1", "comment": "Cloudflare DNS"},
			{"ip": "204.79.141.180", "comment": "Microsoft CDN"}
		]
	}`)
	if err := os.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(filename)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(cfg.Whitelist) != 3 {
		t.Fatalf("expected 3 whitelist entries, got %d", len(cfg.Whitelist))
	}
	if !cfg.IsWhitelistedIP("8.8.8.8") {
		t.Error("expected 8.8.8.8 to be whitelisted")
	}
	if !cfg.IsWhitelistedIP("1.1.1.1") {
		t.Error("expected 1.1.1.1 to be whitelisted")
	}
	if !cfg.IsWhitelistedIP("204.79.141.180") {
		t.Error("expected 204.79.141.180 to be whitelisted")
	}
	if cfg.GetWhitelistComment("8.8.8.8") != "Google DNS" {
		t.Errorf("expected 'Google DNS', got '%s'", cfg.GetWhitelistComment("8.8.8.8"))
	}
	if cfg.GetWhitelistComment("1.1.1.1") != "Cloudflare DNS" {
		t.Errorf("expected 'Cloudflare DNS', got '%s'", cfg.GetWhitelistComment("1.1.1.1"))
	}
}

func TestLoadWhitelistInvalidIP(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_config.json")
	data := []byte(`{
		"whitelist": [
			{"ip": "not-an-ip", "comment": "bad entry"},
			{"ip": "8.8.8.8", "comment": "good entry"},
			{"ip": "8.8.8.8/24", "comment": "cidr entry"}
		]
	}`)
	if err := os.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(filename)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(cfg.Whitelist) != 3 {
		t.Fatalf("expected 3 whitelist entries, got %d", len(cfg.Whitelist))
	}
	if cfg.Whitelist[0].IP != "" {
		t.Errorf("expected invalid IP to be cleared, got '%s'", cfg.Whitelist[0].IP)
	}
	if cfg.Whitelist[1].IP != "8.8.8.8" {
		t.Errorf("expected valid IP to be preserved, got '%s'", cfg.Whitelist[1].IP)
	}
	if cfg.Whitelist[2].IP != "" {
		t.Errorf("expected CIDR IP to be cleared, got '%s'", cfg.Whitelist[2].IP)
	}
}
