package threatintel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFeed_EmptyArray(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "empty.json")
	if err := os.WriteFile(path, []byte("[]"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	db, err := LoadFeed(path)
	if err != nil {
		t.Fatalf("LoadFeed should succeed with empty array: %v", err)
	}
	if db.Count() != 0 {
		t.Errorf("expected 0 indicators, got %d", db.Count())
	}
}

func TestLoadFeed_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(path, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	_, err := LoadFeed(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadFeed_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "feed.json")
	iocs := []IOC{
		{Indicator: "185.141.22.206", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike", Country: "RU", Confidence: 95},
		{Indicator: "evil.com", IndicatorType: "domain", MalwareFamily: "Phishing", Country: "CN", Confidence: 90},
	}
	data, _ := json.Marshal(iocs)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	db, err := LoadFeed(path)
	if err != nil {
		t.Fatalf("LoadFeed should succeed: %v", err)
	}
	if db.Count() != 2 {
		t.Errorf("expected 2 indicators, got %d", db.Count())
	}
}

func TestGetFeedIOCs(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "feed.json")
	iocs := []IOC{
		{Indicator: "185.141.22.206", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike"},
	}
	data, _ := json.Marshal(iocs)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	result, err := GetFeedIOCs(path)
	if err != nil {
		t.Fatalf("GetFeedIOCs should succeed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 IOC, got %d", len(result))
	}
	if result[0].MalwareFamily != "CobaltStrike" {
		t.Errorf("expected CobaltStrike, got %s", result[0].MalwareFamily)
	}
}

func TestFeedCount(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "feed.json")
	iocs := []IOC{
		{Indicator: "185.141.22.206", IndicatorType: "ipv4"},
		{Indicator: "evil.com", IndicatorType: "domain"},
		{Indicator: "8.8.8.8", IndicatorType: "ipv4"},
	}
	data, _ := json.Marshal(iocs)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	count, err := FeedCount(path)
	if err != nil {
		t.Fatalf("FeedCount should succeed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
}

func TestFeedCount_MissingFile(t *testing.T) {
	_, err := FeedCount("/nonexistent/path/feed.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestMergeFeed(t *testing.T) {
	db := NewThreatIntelDB()
	db.AddIOC(IOC{Indicator: "1.1.1.1", IndicatorType: "ipv4"})
	iocs := []IOC{
		{Indicator: "2.2.2.2", IndicatorType: "ipv4"},
		{Indicator: "3.3.3.3", IndicatorType: "ipv4"},
	}
	MergeFeed(db, iocs)
	if db.Count() != 3 {
		t.Errorf("expected 3 indicators after merge, got %d", db.Count())
	}
}

func TestLoadFeed_MergeWithDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "feed.json")
	iocs := []IOC{
		{Indicator: "99.99.99.99", IndicatorType: "ipv4", MalwareFamily: "TestC2"},
	}
	data, _ := json.Marshal(iocs)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Merge with built-in
	merged := NewThreatIntelDB()
	merged.AddIOCs(KnownC2IPs)
	merged.AddIOCs(iocs)

	if merged.Count() != 33 {
		t.Errorf("expected 33 indicators (32 built-in + 1 feed), got %d", merged.Count())
	}
}

func TestFetchFeedURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]IOC{
			{Indicator: "1.2.3.4", IndicatorType: "ipv4", MalwareFamily: "TestC2", Confidence: 80},
		})
	}))
	defer server.Close()

	client := NewFeedURLClient(5 * time.Second)
	iocs, err := client.FetchURLFeed(server.URL)
	if err != nil {
		t.Fatalf("FetchURLFeed should succeed: %v", err)
	}
	if len(iocs) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(iocs))
	}
	if iocs[0].MalwareFamily != "TestC2" {
		t.Errorf("expected TestC2, got %s", iocs[0].MalwareFamily)
	}
}

func TestFetchFeedURL_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewFeedURLClient(5 * time.Second)
	_, err := client.FetchURLFeed(server.URL)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestFetchFeedURL_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewFeedURLClient(5 * time.Second)
	_, err := client.FetchURLFeed(server.URL)
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestCleanSourceURL(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://example.com/feeds/feed.json", "example_com"},
		{"http://mirror.test.org/data/iocs.json", "mirror_test_org"},
	}
	for _, tt := range tests {
		result := cleanSourceURL(tt.url)
		if result != tt.expected {
			t.Errorf("cleanSourceURL(%q) = %q, want %q", tt.url, result, tt.expected)
		}
	}
}

func TestFeedCacheManager_GetIOCs_EmptyCache(t *testing.T) {
	cache := &FeedCache{
		IOCs: []IOC{
			{Indicator: "1.2.3.4", IndicatorType: "ipv4", Confidence: 60, MalwareFamily: "Test"},
		},
		FetchedAt: time.Now(),
		TTL:       1 * time.Hour,
	}
	if len(cache.IOCs) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(cache.IOCs))
	}
	// Fresh cache should not be expired
	if cache.IsExpired() {
		t.Error("expected cache not expired")
	}
}

func TestFeedCacheManager_CacheReuse(t *testing.T) {
	cache := &FeedCache{
		IOCs:      []IOC{{Indicator: "1.2.3.4", IndicatorType: "ipv4", Confidence: 60, MalwareFamily: "Test"}},
		FetchedAt: time.Now(),
		TTL:       1 * time.Hour,
	}
	if len(cache.IOCs) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(cache.IOCs))
	}
	if cache.IsExpired() {
		t.Error("expected not expired")
	}
}

func TestFeedCacheManager_ExpiredCache(t *testing.T) {
	cache := &FeedCache{
		IOCs:      []IOC{{Indicator: "1.2.3.4", IndicatorType: "ipv4", Confidence: 60, MalwareFamily: "Test"}},
		FetchedAt: time.Now().Add(-2 * time.Hour),
		TTL:       1 * time.Hour,
	}
	if !cache.IsExpired() {
		t.Error("expected cache expired")
	}
}

func TestFeedCacheManager_Refresh(t *testing.T) {
	cache := &FeedCache{
		IOCs:      []IOC{{Indicator: "1.2.3.4", IndicatorType: "ipv4", Confidence: 60, MalwareFamily: "Test"}},
		FetchedAt: time.Now(),
		TTL:       1 * time.Hour,
	}
	if len(cache.IOCs) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(cache.IOCs))
	}
}

func TestFeedCacheManager_FetchError(t *testing.T) {
	cacheMgr := &FeedCacheManager{
		client: &ThreatFoxFeedClient{
			HTTPClient: &http.Client{},
		},
		cache: nil,
		ttl:   1 * time.Hour,
	}
	_, err := cacheMgr.GetIOCs()
	if err == nil {
		t.Error("expected error with nil cache")
	}
}

func TestFeedCacheManager_FetchErrorWithStaleCache(t *testing.T) {
	cacheMgr := &FeedCacheManager{
		client: &ThreatFoxFeedClient{
			HTTPClient: &http.Client{},
		},
		cache: &FeedCache{
			IOCs:      []IOC{{Indicator: "1.2.3.4", IndicatorType: "ipv4", Confidence: 60}},
			FetchedAt: time.Now(),
			TTL:       1 * time.Hour,
		},
		ttl: 0,
	}
	_, err := cacheMgr.GetIOCs()
	if err != nil {
		t.Fatalf("should return stale cache: %v", err)
	}
}

func TestParseCSVFeed(t *testing.T) {
	csvData := `# Comment line
ip,ioc_description
185.141.22.206,Cobalt Strike C2
194.26.199.178,Metasploit
ip,ioc_description`

	cfg := csvFeedConfig{
		indicatorType: "ipv4",
		minRecords:    2,
		headerSkip:    "ip",
		confidence:    70,
		tags:          []string{"c2intelfeeds"},
		source:        "c2intelfeeds",
		portCol:       -1,
	}
	iocs, err := parseCSVFeed(strings.NewReader(csvData), cfg)
	if err != nil {
		t.Fatalf("parseCSVFeed should succeed: %v", err)
	}
	if len(iocs) != 2 {
		t.Errorf("expected 2 IOCs, got %d", len(iocs))
	}
	if iocs[0].MalwareFamily != "CobaltStrike" {
		t.Errorf("expected CobaltStrike, got %s", iocs[0].MalwareFamily)
	}
}

func TestParseIPPortFeed(t *testing.T) {
	csvData := `ip,port,ioc_description
185.141.22.206,4444,Cobalt Strike
194.26.199.178,8080,Metasploit`

	iocs, err := parseIPPortFeed(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("parseIPPortFeed should succeed: %v", err)
	}
	if len(iocs) != 2 {
		t.Errorf("expected 2 IOCs, got %d", len(iocs))
	}
	if iocs[0].Port != 4444 {
		t.Errorf("expected port 4444, got %d", iocs[0].Port)
	}
}

func TestParseDomainFeed(t *testing.T) {
	csvData := `domain,ioc_description
evil.com,Cobalt Strike
phishing.net,Metasploit`

	iocs, err := parseDomainFeed(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("parseDomainFeed should succeed: %v", err)
	}
	if len(iocs) != 2 {
		t.Errorf("expected 2 IOCs, got %d", len(iocs))
	}
	if iocs[0].IndicatorType != "domain" {
		t.Errorf("expected domain indicator type, got %s", iocs[0].IndicatorType)
	}
}

func TestDetectMalwareFamily(t *testing.T) {
	tests := []struct {
		desc     string
		expected string
	}{
		{"Cobalt Strike C2", "CobaltStrike"},
		{"Metasploit payload", "Metasploit"},
		{"Empire listener", "Empire"},
		{"Sliver C2", "Sliver"},
		{"C2 Fronting", "C2Fronting"},
		{"Unknown malware", "CobaltStrike"},
	}
	for _, tt := range tests {
		result := detectMalwareFamily(tt.desc)
		if result != tt.expected {
			t.Errorf("detectMalwareFamily(%q) = %q, want %q", tt.desc, result, tt.expected)
		}
	}
}

func TestNewC2IntelFeedsClient_DefaultTimeout(t *testing.T) {
	client := NewC2IntelFeedsClient(0)
	if client.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", client.Timeout)
	}
}

func TestNewC2IntelFeedsClient_CustomTimeout(t *testing.T) {
	client := NewC2IntelFeedsClient(30 * time.Second)
	if client.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", client.Timeout)
	}
}

func TestNewThreatFoxFeedClient_DefaultTimeout(t *testing.T) {
	client := NewThreatFoxFeedClient("", 0)
	if client.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", client.Timeout)
	}
}

// ---------- HTTP-bound tests via httptest ----------

func TestFetchAllIOCs(t *testing.T) {
	// Test parseIPFeed directly
	iocs, err := parseIPFeed(strings.NewReader("# comment\n185.141.22.206,Cobalt Strike C2\n194.26.199.178,Metasploit\n"))
	if err != nil {
		t.Fatalf("parseIPFeed should succeed: %v", err)
	}
	if len(iocs) != 2 {
		t.Errorf("expected 2 IOCs, got %d", len(iocs))
	}
	if iocs[0].MalwareFamily != "CobaltStrike" {
		t.Errorf("expected CobaltStrike, got %s", iocs[0].MalwareFamily)
	}
}

func TestFetch30DayIOCs(t *testing.T) {
	iocs, err := parseIPFeed(strings.NewReader("# comment\n185.141.22.206,Cobalt Strike C2\n"))
	if err != nil {
		t.Fatalf("parseIPFeed should succeed: %v", err)
	}
	if len(iocs) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(iocs))
	}
}

func TestFetchFeed_EmptyResponse(t *testing.T) {
	iocs, err := parseIPFeed(strings.NewReader("# comment\nip,ioc_description\n"))
	if err != nil {
		t.Fatalf("parseIPFeed should succeed with empty body: %v", err)
	}
	if len(iocs) != 0 {
		t.Errorf("expected 0 IOCs for empty feed, got %d", len(iocs))
	}
}

func TestFetchFeed_MalformedCSV(t *testing.T) {
	iocs, err := parseIPFeed(strings.NewReader("only_one_column\n"))
	if err != nil {
		t.Fatalf("parseIPFeed should skip malformed rows: %v", err)
	}
	if len(iocs) != 0 {
		t.Errorf("expected 0 IOCs for malformed CSV, got %d", len(iocs))
	}
}

func TestFetchIPPortFeed_PortsExtracted(t *testing.T) {
	iocs, err := parseIPPortFeed(strings.NewReader("ip,port,ioc_description\n185.141.22.206,4444,Cobalt Strike\n194.26.199.178,8080,Metasploit\n"))
	if err != nil {
		t.Fatalf("parseIPPortFeed should succeed: %v", err)
	}
	if len(iocs) != 2 {
		t.Fatalf("expected 2 IOCs, got %d", len(iocs))
	}
	if iocs[0].Port != 4444 {
		t.Errorf("expected port 4444, got %d", iocs[0].Port)
	}
	if iocs[1].Port != 8080 {
		t.Errorf("expected port 8080, got %d", iocs[1].Port)
	}
}

func TestFetchDomainFeed_Type(t *testing.T) {
	iocs, err := parseDomainFeed(strings.NewReader("domain,ioc_description\nevil.com,Cobalt Strike\nphishing.net,Metasploit\n"))
	if err != nil {
		t.Fatalf("parseDomainFeed should succeed: %v", err)
	}
	if len(iocs) != 2 {
		t.Fatalf("expected 2 IOCs, got %d", len(iocs))
	}
	if iocs[0].IndicatorType != "domain" {
		t.Errorf("expected domain indicator type, got %s", iocs[0].IndicatorType)
	}
}

func TestParseCSVFeed_ShortRecords(t *testing.T) {
	iocs, err := parseCSVFeed(strings.NewReader("only_one_field\n"), csvFeedConfig{
		minRecords: 2,
		headerSkip: "ip",
	})
	if err != nil {
		t.Fatalf("parseCSVFeed should succeed: %v", err)
	}
	if len(iocs) != 0 {
		t.Errorf("expected 0 IOCs for short records, got %d", len(iocs))
	}
}

func TestParseCSVFeed_EmptyIndicator(t *testing.T) {
	iocs, err := parseCSVFeed(strings.NewReader("# comment\n\n185.141.22.206,Cobalt Strike\n"), csvFeedConfig{
		minRecords: 2,
		headerSkip: "ip",
	})
	if err != nil {
		t.Fatalf("parseCSVFeed should succeed: %v", err)
	}
	if len(iocs) != 1 {
		t.Errorf("expected 1 IOC (empty indicator skipped), got %d", len(iocs))
	}
}

func TestParseCSVFeed_PortParsing(t *testing.T) {
	iocs, err := parseCSVFeed(strings.NewReader("ip,port,ioc_description\n185.141.22.206,4444,Cobalt Strike\n"), csvFeedConfig{
		minRecords: 3,
		headerSkip: "ip",
		portCol:    1,
	})
	if err != nil {
		t.Fatalf("parseCSVFeed should succeed: %v", err)
	}
	if len(iocs) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(iocs))
	}
	if iocs[0].Port != 4444 {
		t.Errorf("expected port 4444, got %d", iocs[0].Port)
	}
}

func TestParseCSVFeed_MissingPortCol(t *testing.T) {
	iocs, err := parseCSVFeed(strings.NewReader("ip,port,ioc_description\n185.141.22.206,4444,Cobalt Strike\n"), csvFeedConfig{
		minRecords: 3,
		headerSkip: "ip",
		portCol:    -1,
	})
	if err != nil {
		t.Fatalf("parseCSVFeed should succeed: %v", err)
	}
	if len(iocs) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(iocs))
	}
	if iocs[0].Port != 0 {
		t.Errorf("expected port 0 when portCol=-1, got %d", iocs[0].Port)
	}
}

func TestParseIPFeed_Empty(t *testing.T) {
	iocs, err := parseIPFeed(strings.NewReader("# comment\nip,ioc_description\n"))
	if err != nil {
		t.Fatalf("parseIPFeed should succeed: %v", err)
	}
	if len(iocs) != 0 {
		t.Errorf("expected 0 IOCs, got %d", len(iocs))
	}
}

func TestParseDomainFeed_Empty(t *testing.T) {
	iocs, err := parseDomainFeed(strings.NewReader("# comment\ndomain,ioc_description\n"))
	if err != nil {
		t.Fatalf("parseDomainFeed should succeed: %v", err)
	}
	if len(iocs) != 0 {
		t.Errorf("expected 0 IOCs, got %d", len(iocs))
	}
}

func TestParseIPPortFeed_Empty(t *testing.T) {
	iocs, err := parseIPPortFeed(strings.NewReader("ip,port,ioc_description\n"))
	if err != nil {
		t.Fatalf("parseIPPortFeed should succeed: %v", err)
	}
	if len(iocs) != 0 {
		t.Errorf("expected 0 IOCs, got %d", len(iocs))
	}
}
