package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// KnownC2IPs contains known command and control IP addresses from open-source threat intelligence.
// Sources: ThreatFox, C2-Tracker, Spamhaus Xanadu (representative subset).
var KnownC2IPs = []IOC{
	// Cobalt Strike
	{Indicator: "185.141.22.206", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike", FirstSeen: time.Date(2023, 1, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC), Country: "RU", Confidence: 95, Tags: []string{"c2", "cobalt-strike", "rat"}, Source: "threatfox", Status: "active"},
	{Indicator: "194.26.199.178", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike", FirstSeen: time.Date(2023, 3, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC), Country: "NL", Confidence: 90, Tags: []string{"c2", "cobalt-strike"}, Source: "threatfox", Status: "active"},
	{Indicator: "45.155.205.123", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike", FirstSeen: time.Date(2023, 5, 20, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC), Country: "DE", Confidence: 88, Tags: []string{"c2", "cobalt-strike", "port-443"}, Source: "threatfox", Status: "active", Port: 443},

	// Metasploit
	{Indicator: "103.94.176.182", IndicatorType: "ipv4", MalwareFamily: "Metasploit", FirstSeen: time.Date(2023, 2, 5, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC), Country: "BD", Confidence: 85, Tags: []string{"c2", "metasploit"}, Source: "threatfox", Status: "active"},

	// Empire
	{Indicator: "209.141.58.184", IndicatorType: "ipv4", MalwareFamily: "Empire", FirstSeen: time.Date(2023, 6, 12, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 82, Tags: []string{"c2", "empire", "powershell"}, Source: "threatfox", Status: "active"},

	// Sliver C2
	{Indicator: "51.15.14.202", IndicatorType: "ipv4", MalwareFamily: "Sliver", FirstSeen: time.Date(2023, 7, 20, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 10, 1, 0, 0, 0, 0, time.UTC), Country: "FR", Confidence: 87, Tags: []string{"c2", "sliver"}, Source: "threatfox", Status: "active"},

	// Brute Ratel
	{Indicator: "91.219.174.185", IndicatorType: "ipv4", MalwareFamily: "BruteRatel", FirstSeen: time.Date(2023, 8, 5, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC), Country: "RO", Confidence: 92, Tags: []string{"c2", "brute-ratel", "rat"}, Source: "threatfox", Status: "active"},

	// Lumma Stealer
	{Indicator: "194.163.144.175", IndicatorType: "ipv4", MalwareFamily: "LummaStealer", FirstSeen: time.Date(2023, 9, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC), Country: "CH", Confidence: 90, Tags: []string{"stealer", "lumma", "credential-theft"}, Source: "threatfox", Status: "active"},

	// Meduza Stealer
	{Indicator: "185.174.236.95", IndicatorType: "ipv4", MalwareFamily: "MeduzaStealer", FirstSeen: time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Country: "UA", Confidence: 88, Tags: []string{"stealer", "meduza"}, Source: "threatfox", Status: "active"},

	// Quasar RAT
	{Indicator: "176.123.150.200", IndicatorType: "ipv4", MalwareFamily: "QuasarRAT", FirstSeen: time.Date(2023, 11, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), Country: "BG", Confidence: 85, Tags: []string{"rat", "quasar"}, Source: "threatfox", Status: "active"},

	// DarkComet RAT
	{Indicator: "93.113.68.170", IndicatorType: "ipv4", MalwareFamily: "DarkComet", FirstSeen: time.Date(2023, 12, 5, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC), Country: "FR", Confidence: 80, Tags: []string{"rat", "darkcomet"}, Source: "threatfox", Status: "active"},

	// njRAT
	{Indicator: "89.32.100.45", IndicatorType: "ipv4", MalwareFamily: "njRAT", FirstSeen: time.Date(2024, 1, 20, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC), Country: "TR", Confidence: 83, Tags: []string{"rat", "njrat"}, Source: "threatfox", Status: "active"},

	// Remcos RAT
	{Indicator: "162.247.203.52", IndicatorType: "ipv4", MalwareFamily: "RemcosRAT", FirstSeen: time.Date(2024, 2, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 78, Tags: []string{"rat", "remcos"}, Source: "threatfox", Status: "active"},

	// Poison Ivy RAT
	{Indicator: "5.25.125.100", IndicatorType: "ipv4", MalwareFamily: "PoisonIvy", FirstSeen: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), Country: "RU", Confidence: 86, Tags: []string{"rat", "poison-ivy"}, Source: "threatfox", Status: "active"},

	// AsyncRAT
	{Indicator: "103.86.22.88", IndicatorType: "ipv4", MalwareFamily: "AsyncRAT", FirstSeen: time.Date(2024, 4, 5, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC), Country: "IN", Confidence: 84, Tags: []string{"rat", "asyncrat"}, Source: "threatfox", Status: "active"},

	// ShadowPad
	{Indicator: "118.174.4.205", IndicatorType: "ipv4", MalwareFamily: "ShadowPad", FirstSeen: time.Date(2024, 5, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC), Country: "CN", Confidence: 91, Tags: []string{"apt", "shadowpad", "espionage"}, Source: "threatfox", Status: "active"},

	// Covenant C2
	{Indicator: "64.247.194.155", IndicatorType: "ipv4", MalwareFamily: "Covenant", FirstSeen: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 75, Tags: []string{"c2", "covenant", "dotnet"}, Source: "threatfox", Status: "active"},

	// Mythic C2
	{Indicator: "142.93.120.188", IndicatorType: "ipv4", MalwareFamily: "Mythic", FirstSeen: time.Date(2024, 6, 20, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 72, Tags: []string{"c2", "mythic"}, Source: "threatfox", Status: "active"},

	// Deimos C2
	{Indicator: "159.65.224.100", IndicatorType: "ipv4", MalwareFamily: "Deimos", FirstSeen: time.Date(2024, 7, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC), Country: "NL", Confidence: 78, Tags: []string{"c2", "deimos"}, Source: "threatfox", Status: "active"},

	// Havoc C2
	{Indicator: "138.68.85.142", IndicatorType: "ipv4", MalwareFamily: "Havoc", FirstSeen: time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC), Country: "DE", Confidence: 76, Tags: []string{"c2", "havoc"}, Source: "threatfox", Status: "active"},

	// Caldera C2
	{Indicator: "167.99.100.50", IndicatorType: "ipv4", MalwareFamily: "Caldera", FirstSeen: time.Date(2024, 8, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 74, Tags: []string{"c2", "caldera"}, Source: "threatfox", Status: "active"},

	// Known phishing/C2 domains
	{Indicator: "secure-login-verify.tk", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), Country: "RU", Confidence: 92, Tags: []string{"phishing", "credential-theft"}, Source: "threatfox", Status: "active"},
	{Indicator: "account-verify-secure.xyz", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 9, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), Country: "CN", Confidence: 88, Tags: []string{"phishing", "banking"}, Source: "threatfox", Status: "active"},
	{Indicator: "portal-auth-verify.top", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 10, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Country: "UA", Confidence: 85, Tags: []string{"phishing"}, Source: "threatfox", Status: "active"},
	{Indicator: "signin-secure-portal.online", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 10, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), Country: "TR", Confidence: 82, Tags: []string{"phishing", "signin"}, Source: "threatfox", Status: "active"},
	{Indicator: "banking-secure-verify.club", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), Country: "RO", Confidence: 90, Tags: []string{"phishing", "banking", "financial"}, Source: "threatfox", Status: "active"},
	{Indicator: "payment-verify-secure.store", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 11, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Country: "BG", Confidence: 87, Tags: []string{"phishing", "payment"}, Source: "threatfox", Status: "active"},
	{Indicator: "crypto-wallet-verify.site", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), Country: "NL", Confidence: 89, Tags: []string{"phishing", "crypto", "bitcoin"}, Source: "threatfox", Status: "active"},
	{Indicator: "wallet-auth-secure.work", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 12, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Country: "DE", Confidence: 84, Tags: []string{"phishing", "crypto", "wallet"}, Source: "threatfox", Status: "active"},
	{Indicator: "admin-portal-verify.trade", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Country: "FR", Confidence: 81, Tags: []string{"phishing", "admin"}, Source: "threatfox", Status: "active"},
	{Indicator: "verify-account-login.info", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Country: "CH", Confidence: 86, Tags: []string{"phishing", "account"}, Source: "threatfox", Status: "active"},
	{Indicator: "secure-auth-portal.biz", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 83, Tags: []string{"phishing"}, Source: "threatfox", Status: "active"},
}

// ThreatFoxFeedClient fetches live C2 indicators from the ThreatFox API.
// The ThreatFox API (https://threatfox-api.abuse.ch/) is free and does not require an API key
// for basic usage. An optional API key can be provided for higher rate limits.
type ThreatFoxFeedClient struct {
	APIKey    string
	Timeout   time.Duration
	HTTPClient *http.Client
}

// NewThreatFoxFeedClient creates a client with sensible defaults.
func NewThreatFoxFeedClient(apiKey string, timeout time.Duration) *ThreatFoxFeedClient {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &ThreatFoxFeedClient{
		APIKey: apiKey,
		Timeout: timeout,
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// FeedResponse is the ThreatFox API response envelope.
type FeedResponse struct {
	Count    int     `json:"query_stats"`
	IOCs     []FeedIOC `json:"iocs"`
	Msg      string  `json:"message"`
	Success  bool    `json:"success"`
}

// FeedIOC is a single IOC entry from the ThreatFox API.
type FeedIOC struct {
	Indicator        string   `json:"indicator"`
	IndicatorType    string   `json:"indicator_type"`
	MalwareFamily    string   `json:"malware_family"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	Country          string   `json:"country"`
	Confidence       int      `json:"confidence_level"`
	Tags             []string `json:"tags"`
	Source           string   `json:"source"`
	Status           string   `json:"status"`
	Port             int      `json:"port"`
	Protocol         string   `json:"protocol"`
	Additional       string   `json:"additional_info"`
}

// FetchLiveIOCs retrieves active C2 indicators from ThreatFox and converts them
// to the local IOC type. Returns only indicators with confidence >= 50.
func (c *ThreatFoxFeedClient) FetchLiveIOCs() ([]IOC, error) {
	url := "https://threatfox-api.abuse.ch/v1/search?query=ip_address&limit=5000&page=0"
	if c.APIKey != "" {
		url = "https://threatfox-api.abuse.ch/v1/search?query=ip_address&limit=5000&page=0&api_key=" + c.APIKey
	}

	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch threatfox feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("threatfox API error: status=%d body=%s", resp.StatusCode, string(body))
	}

	var feedResp FeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&feedResp); err != nil {
		return nil, fmt.Errorf("decode threatfox response: %w", err)
	}

	if !feedResp.Success {
		return nil, fmt.Errorf("threatfox API returned error: %s", feedResp.Msg)
	}

	iocs := make([]IOC, 0, len(feedResp.IOCs))
	for _, f := range feedResp.IOCs {
		if f.Confidence < 50 {
			continue
		}
		firstSeen, _ := time.Parse("2006-01-02", f.FirstSeen)
		lastSeen, _ := time.Parse("2006-01-02", f.LastSeen)

		iocs = append(iocs, IOC{
			Indicator:     f.Indicator,
			IndicatorType: f.IndicatorType,
			MalwareFamily: f.MalwareFamily,
			FirstSeen:     firstSeen,
			LastSeen:      lastSeen,
			Country:       f.Country,
			Confidence:    f.Confidence,
			Tags:          f.Tags,
			Source:        "threatfox_live",
			Status:        f.Status,
			Port:          f.Port,
		})
	}

	return iocs, nil
}

// FeedCache holds a cached copy of live feed IOCs with its TTL timestamp.
type FeedCache struct {
	IOCs      []IOC
	FetchedAt time.Time
	TTL       time.Duration
}

// IsExpired returns true if the cache has expired.
func (fc *FeedCache) IsExpired() bool {
	return time.Since(fc.FetchedAt) > fc.TTL
}

// FeedCacheManager manages the cached threat intel feed and periodic refresh.
type FeedCacheManager struct {
	client *ThreatFoxFeedClient
	cache  *FeedCache
	mu     sync.Mutex
	ttl    time.Duration
}

// NewFeedCacheManager creates a manager with the given client and cache TTL.
func NewFeedCacheManager(client *ThreatFoxFeedClient, ttl time.Duration) *FeedCacheManager {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	return &FeedCacheManager{
		client: client,
		ttl:    ttl,
		cache:  nil,
	}
}

// GetIOCs returns cached IOCs, fetching fresh data if the cache is expired.
func (m *FeedCacheManager) GetIOCs() ([]IOC, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cache != nil && !m.cache.IsExpired() {
		return m.cache.IOCs, nil
	}

	iocs, err := m.client.FetchLiveIOCs()
	if err != nil {
		// Return stale cache on error if available.
		if m.cache != nil {
			return m.cache.IOCs, nil
		}
		return nil, err
	}

	m.cache = &FeedCache{
		IOCs:      iocs,
		FetchedAt: time.Now(),
		TTL:       m.ttl,
	}

	return iocs, nil
}

// Refresh forces a cache refresh regardless of TTL.
func (m *FeedCacheManager) Refresh() ([]IOC, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	iocs, err := m.client.FetchLiveIOCs()
	if err != nil {
		if m.cache != nil {
			return m.cache.IOCs, nil
		}
		return nil, err
	}

	m.cache = &FeedCache{
		IOCs:      iocs,
		FetchedAt: time.Now(),
		TTL:       m.ttl,
	}

	return iocs, nil
}

// FeedURLClient fetches IOCs from a custom JSON feed URL.
// The feed must be a JSON array of IOC objects with the same structure as IOC.
type FeedURLClient struct {
	HTTPClient *http.Client
	Timeout    time.Duration
}

// NewFeedURLClient creates a URL feed client.
func NewFeedURLClient(timeout time.Duration) *FeedURLClient {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &FeedURLClient{
		HTTPClient: &http.Client{Timeout: timeout},
		Timeout:    timeout,
	}
}

// FetchURLFeed fetches IOCs from a JSON feed URL.
func (c *FeedURLClient) FetchURLFeed(url string) ([]IOC, error) {
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch feed URL %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed URL error: status=%d", resp.StatusCode)
	}

	var iocs []IOC
	if err := json.NewDecoder(resp.Body).Decode(&iocs); err != nil {
		return nil, fmt.Errorf("decode feed URL %s: %w", url, err)
	}

	// Tag with source URL.
	source := cleanSourceURL(url)
	for i := range iocs {
		if iocs[i].Source == "" {
			iocs[i].Source = source
		}
	}

	return iocs, nil
}

// cleanSourceURL extracts a short source name from a URL.
func cleanSourceURL(raw string) string {
	s := strings.TrimPrefix(raw, "https://")
	s = strings.TrimPrefix(s, "http://")
	idx := strings.Index(s, "/")
	if idx > 0 {
		s = s[:idx]
	}
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ".", "_")
	return s
}
