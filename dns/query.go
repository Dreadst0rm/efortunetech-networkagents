package dns

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Query represents a single DNS query observation.
type Query struct {
	PID       int
	Process   string
	QueryName string
	QueryType string
	Responses []string
	Timestamp time.Time
}

// QueryLog is a thread-safe DNS query logger.
type QueryLog struct {
	mu     sync.Mutex
	queries []Query
}

// NewQueryLog creates a new DNS query log.
func NewQueryLog() *QueryLog {
	return &QueryLog{}
}

// AddRecord appends a DNS query observation.
func (l *QueryLog) AddRecord(q Query) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.queries = append(l.queries, q)
}

// GetQueries returns all recorded queries.
func (l *QueryLog) GetQueries() []Query {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Query, len(l.queries))
	copy(out, l.queries)
	return out
}

// Clear removes all recorded queries.
func (l *QueryLog) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.queries = nil
}

// SuspiciousDomainResult holds the result of domain suspicion analysis.
type SuspiciousDomainResult struct {
	Domain     string
	IsSuspicious bool
	Reason     string
	Confidence float64
}

// suspiciousTLDs are TLDs commonly associated with malicious activity.
var suspiciousTLDs = map[string]float64{
	".xyz":  0.6, ".top": 0.5, ".club": 0.5, ".online": 0.5,
	".store": 0.5, ".site": 0.5, ".work": 0.4, ".trade": 0.5,
	".info": 0.4, ".biz": 0.4, ".ru": 0.6, ".cn": 0.5,
	".tk": 0.7, ".ml": 0.7, ".ga": 0.7, ".cf": 0.7,
}

// suspiciousKeywords are substrings commonly found in DGA or C2 domains.
var suspiciousKeywords = []string{
	"login", "account", "secure", "verify", "update", "admin",
	"portal", "signin", "auth", "banking", "payment", "wallet",
	"crypto", "bitcoin", "ethereum", "exchange",
}

// CheckDomain evaluates whether a domain name appears suspicious.
func CheckDomain(domain string) SuspiciousDomainResult {
	domain = strings.ToLower(domain)
	if domain == "" {
		return SuspiciousDomainResult{Confidence: 0}
	}

	var score float64
	var reasons []string

	// Check TLD
	for tld, baseScore := range suspiciousTLDs {
		if strings.HasSuffix(domain, tld) {
			score += baseScore
			reasons = append(reasons, fmt.Sprintf("suspicious TLD: %s", tld))
		}
	}

	// Check for high subdomain depth (DGA indicator)
	depth := strings.Count(domain, ".")
	if depth >= 4 {
		score += 0.3
		reasons = append(reasons, "high subdomain depth")
	}

	// Check for suspicious keywords
	for _, kw := range suspiciousKeywords {
		if strings.Contains(domain, kw) {
			score += 0.2
			reasons = append(reasons, fmt.Sprintf("keyword match: %s", kw))
			break
		}
	}

	// Check for long domain names (DGA indicator)
	if len(domain) > 50 {
		score += 0.4
		reasons = append(reasons, "unusually long domain name")
	}

	// Check for high consonant ratio (DGA indicator)
	consonants := 0
	vowels := 0
	for _, r := range domain {
		lower := strings.ToLower(string(r))
		if lower >= "a" && lower <= "z" {
			if isVowel(r) {
				vowels++
			} else {
				consonants++
			}
		}
	}
	if vowels > 0 && float64(consonants)/float64(vowels) > 5.0 {
		score += 0.3
		reasons = append(reasons, "high consonant-to-vowel ratio")
	}

	if score > 0 {
		if score >= 1.0 {
			score = 1.0
		}
		return SuspiciousDomainResult{
			Domain:       domain,
			IsSuspicious: score >= 0.6,
			Reason:     strings.Join(reasons, "; "),
			Confidence: score,
		}
	}

	return SuspiciousDomainResult{Domain: domain}
}

func isVowel(r rune) bool {
	s := string(r)
	vowels := "aeiouAEIOU"
	return strings.Contains(vowels, s)
}

// CaptureResult holds the output of a DNS capture operation.
type CaptureResult struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	QueryLog  *QueryLog `json:"query_log"`
	Queries   []Query   `json:"queries"`
	Suspicious []SuspiciousDomainResult `json:"suspicious_domains,omitempty"`
	CaptureMethod string `json:"capture_method"`
}

// SaveCaptureResult writes the DNS capture result to a JSON file.
func SaveCaptureResult(result *CaptureResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal capture result: %w", err)
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("write capture result: %w", err)
	}
	return nil
}
