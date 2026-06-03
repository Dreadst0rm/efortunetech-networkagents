package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds all configurable thresholds and settings.
type Config struct {
	Thresholds Thresholds `json:"thresholds"`
	Excluded   Excluded   `json:"excluded"`
}

// Thresholds holds numeric thresholds for risk heuristics.
type Thresholds struct {
	// MinIPConnections is the minimum connection count to a single remote IP to trigger a risk flag.
	MinIPConnections int `json:"min_ip_connections"`
	// MinProcessConnections is the minimum outbound connection count per process to trigger a risk flag.
	MinProcessConnections int `json:"min_process_connections"`
	// CriticalThreshold is the number of triggered heuristics to classify a connection as critical.
	CriticalThreshold int `json:"critical_threshold"`
	// HighThreshold is the number of triggered heuristics to classify a connection as high risk.
	HighThreshold int `json:"high_threshold"`
}

// Excluded holds lists of PIDs and processes to skip during scanning.
type Excluded struct {
	PIDs      []int    `json:"pids"`
	Processes []string `json:"processes"`
}

// Defaults returns a Config with built-in default values.
func Defaults() Config {
	return Config{
		Thresholds: Thresholds{
			MinIPConnections:    5,
			MinProcessConnections: 5,
			CriticalThreshold:   3,
			HighThreshold:       2,
		},
		Excluded: Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}
}

// Load reads a config file and merges it with defaults.
func Load(filename string) (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}

// IsExcludedPID returns true if the given PID is in the exclusion list.
func (c *Config) IsExcludedPID(pid int) bool {
	for _, p := range c.Excluded.PIDs {
		if p == pid {
			return true
		}
	}
	return false
}

// IsExcludedProcess returns true if the given process name is in the exclusion list.
func (c *Config) IsExcludedProcess(name string) bool {
	for _, p := range c.Excluded.Processes {
		if p == name {
			return true
		}
	}
	return false
}
