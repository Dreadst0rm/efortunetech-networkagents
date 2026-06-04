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
	DNSLog     bool       `json:"dns_log"`
	Alerting   Alerting   `json:"alerting"`
}

// Alerting holds alert delivery configuration.
type Alerting struct {
	WebhookURL string `json:"webhook_url"`
	Enabled    bool   `json:"enabled"`
}

// Thresholds holds numeric thresholds for risk heuristics.
type Thresholds struct {
	MinIPConnections        int `json:"min_ip_connections"`
	MinProcessConnections   int `json:"min_process_connections"`
	CriticalThreshold       int `json:"critical_threshold"`
	HighThreshold           int `json:"high_threshold"`
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
			MinIPConnections:        5,
			MinProcessConnections:   5,
			CriticalThreshold:       3,
			HighThreshold:           2,
		},
		Excluded: Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
		DNSLog: false,
		Alerting: Alerting{
			WebhookURL: "",
			Enabled:    false,
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

	var partial struct {
		Thresholds *Thresholds `json:"thresholds"`
		Excluded   *Excluded   `json:"excluded"`
		DNSLog     *bool       `json:"dns_log"`
		Alerting   *Alerting   `json:"alerting"`
	}
	if err := json.Unmarshal(data, &partial); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if partial.Thresholds != nil {
		cfg.Thresholds = *partial.Thresholds
		if cfg.Thresholds.MinIPConnections < 0 {
			cfg.Thresholds.MinIPConnections = 0
		}
		if cfg.Thresholds.MinProcessConnections < 0 {
			cfg.Thresholds.MinProcessConnections = 0
		}
		if cfg.Thresholds.CriticalThreshold < 1 {
			cfg.Thresholds.CriticalThreshold = 1
		}
		if cfg.Thresholds.HighThreshold < 1 {
			cfg.Thresholds.HighThreshold = 1
		}
	}
	if partial.Excluded != nil {
		cfg.Excluded = *partial.Excluded
	}
	if partial.DNSLog != nil {
		cfg.DNSLog = *partial.DNSLog
	}
	if partial.Alerting != nil {
		cfg.Alerting = *partial.Alerting
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
