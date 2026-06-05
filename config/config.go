package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// WhitelistedIP represents an IP address trusted by the administrator.
type WhitelistedIP struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
	parsed  net.IP
}

// Config holds all configurable thresholds and settings.
type Config struct {
	Thresholds Thresholds      `json:"thresholds"`
	Excluded   Excluded        `json:"excluded"`
	Whitelist  []WhitelistedIP `json:"whitelist"`
	DNSLog     bool            `json:"dns_log"`
	Alerting   Alerting        `json:"alerting"`
}

// Alerting holds alert delivery configuration.
type Alerting struct {
	WebhookURL string `json:"webhook_url"`
	Enabled    bool   `json:"enabled"`
}

// Thresholds holds numeric thresholds for risk heuristics.
type Thresholds struct {
	MinIPConnections      int `json:"min_ip_connections"`
	MinProcessConnections int `json:"min_process_connections"`
	CriticalThreshold     int `json:"critical_threshold"`
	HighThreshold         int `json:"high_threshold"`
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
			MinIPConnections:      5,
			MinProcessConnections: 5,
			CriticalThreshold:     3,
			HighThreshold:         2,
		},
		Excluded: Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
		Whitelist: []WhitelistedIP{},
		DNSLog:    false,
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
		Thresholds *Thresholds      `json:"thresholds"`
		Excluded   *Excluded        `json:"excluded"`
		Whitelist  *[]WhitelistedIP `json:"whitelist"`
		DNSLog     *bool            `json:"dns_log"`
		Alerting   *Alerting        `json:"alerting"`
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
		if cfg.Thresholds.CriticalThreshold < cfg.Thresholds.HighThreshold {
			cfg.Thresholds.CriticalThreshold = cfg.Thresholds.HighThreshold
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
	if partial.Whitelist != nil {
		cfg.Whitelist = *partial.Whitelist
		for i, w := range cfg.Whitelist {
			if net.ParseIP(w.IP) == nil {
				cfg.Whitelist[i].IP = ""
			} else {
				cfg.Whitelist[i].parsed = net.ParseIP(w.IP)
			}
		}
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

// IsWhitelistedIP returns true if the given IP is in the whitelist.
func (c *Config) IsWhitelistedIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, w := range c.Whitelist {
		pw := w.parsed
		if pw == nil {
			pw = net.ParseIP(w.IP)
		}
		if pw != nil && pw.Equal(parsed) {
			return true
		}
	}
	return false
}

// GetWhitelistComment returns the comment for a whitelisted IP, or empty string.
func (c *Config) GetWhitelistComment(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	for _, w := range c.Whitelist {
		pw := w.parsed
		if pw == nil {
			pw = net.ParseIP(w.IP)
		}
		if pw != nil && pw.Equal(parsed) {
			return w.Comment
		}
	}
	return ""
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
