package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// WhitelistedIP represents an IP address trusted by the administrator.
type WhitelistedIP struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
	parsed  net.IP
}

// ipIndex is a pre-computed map from lowercase IP string to whitelist entry
// for O(1) lookups instead of O(n) linear scans.
type ipIndex map[string]whitelistEntry

type whitelistEntry struct {
	ip      string
	parsed  net.IP
	comment string
}

// Config holds all configurable thresholds and settings.
type Config struct {
	Thresholds     Thresholds        `json:"thresholds"`
	Excluded       Excluded          `json:"excluded"`
	Whitelist      []WhitelistedIP   `json:"whitelist"`
	DNSLog         bool              `json:"dns_log"`
	DNS            DNSConfig         `json:"dns"`
	Alerting       Alerting          `json:"alerting"`
	ThreatIntel    ThreatIntelConfig `json:"threat_intel"`
	ipIndex        ipIndex           // pre-computed for O(1) lookups
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

// DNSConfig holds DNS lookup behavior settings.
type DNSConfig struct {
	LookupConcurrency int `json:"lookup_concurrency"` // max concurrent reverse DNS lookups (0 = default 10)
}

// ThreatIntelConfig holds live threat intelligence feed settings.
type ThreatIntelConfig struct {
	Enabled      bool   `json:"enabled"`
	RefreshIntvl int    `json:"refresh_interval"` // seconds between auto-refreshes (0 = disabled)
	APIKey       string `json:"api_key"`          // ThreatFox API key (optional, many endpoints don't require it)
	Timeout      int    `json:"timeout"`          // HTTP request timeout in seconds (0 = default 10)
	FeedURL      string `json:"feed_url"`         // custom feed URL (overrides built-in ThreatFox)
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
		DNS: DNSConfig{
			LookupConcurrency: 10,
		},
		ThreatIntel: ThreatIntelConfig{
			RefreshIntvl: 3600, // 1 hour default
			Timeout:      10,
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
		Thresholds   *Thresholds        `json:"thresholds"`
		Excluded     *Excluded          `json:"excluded"`
		Whitelist    *[]WhitelistedIP   `json:"whitelist"`
		DNSLog       *bool              `json:"dns_log"`
		DNS          *DNSConfig         `json:"dns"`
		Alerting     *Alerting          `json:"alerting"`
		ThreatIntel  *ThreatIntelConfig `json:"threat_intel"`
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
	if partial.DNS != nil {
		cfg.DNS = *partial.DNS
		if cfg.DNS.LookupConcurrency <= 0 {
			cfg.DNS.LookupConcurrency = 10
		}
	}
	if partial.Alerting != nil {
		cfg.Alerting = *partial.Alerting
	}
	if partial.ThreatIntel != nil {
		cfg.ThreatIntel = *partial.ThreatIntel
		if cfg.ThreatIntel.Timeout <= 0 {
			cfg.ThreatIntel.Timeout = 10
		}
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

	// Build pre-computed IP index for O(1) whitelist lookups.
	cfg.buildIPIndex()

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

// buildIPIndex pre-computes a map from lowercase IP string to whitelist entry
// for O(1) lookups during risk assessment.
func (c *Config) buildIPIndex() {
	if len(c.Whitelist) == 0 {
		return
	}
	idx := make(ipIndex, len(c.Whitelist))
	for _, w := range c.Whitelist {
		parsed := w.parsed
		if parsed == nil {
			parsed = net.ParseIP(w.IP)
		}
		if parsed != nil {
			idx[strings.ToLower(w.IP)] = whitelistEntry{
				ip:      w.IP,
				parsed:  parsed,
				comment: w.Comment,
			}
		}
	}
	c.ipIndex = idx
}

// IsWhitelistedIP returns true if the given IP is in the whitelist.
func (c *Config) IsWhitelistedIP(ip string) bool {
	if c.ipIndex == nil {
		// Fallback to linear scan if index not built (e.g., Defaults()).
		return c.isWhitelistedIPLinear(ip)
	}
	entry, ok := c.ipIndex[ip]
	if !ok {
		// Also try lowercase fallback for edge cases.
		entry, ok = c.ipIndex[strings.ToLower(ip)]
	}
	return ok && entry.parsed != nil && entry.parsed.Equal(net.ParseIP(ip))
}

// isWhitelistedIPLinear is the fallback O(n) whitelist check.
func (c *Config) isWhitelistedIPLinear(ip string) bool {
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
	if c.ipIndex != nil {
		entry, ok := c.ipIndex[ip]
		if !ok {
			entry, ok = c.ipIndex[strings.ToLower(ip)]
		}
		if ok && entry.parsed != nil && entry.parsed.Equal(net.ParseIP(ip)) {
			return entry.comment
		}
	}
	// Fallback to linear scan.
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
