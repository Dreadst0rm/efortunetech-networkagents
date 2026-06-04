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
