package threatintel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFeed_EmptyArray(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "empty.json")
	os.WriteFile(path, []byte("[]"), 0644)
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
	os.WriteFile(path, []byte("not valid json"), 0644)
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
	os.WriteFile(path, data, 0644)

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
	os.WriteFile(path, data, 0644)

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
	os.WriteFile(path, data, 0644)

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
	os.WriteFile(path, data, 0644)

	// Merge with built-in
	merged := NewThreatIntelDB()
	merged.AddIOCs(KnownC2IPs)
	merged.AddIOCs(iocs)

	if merged.Count() != 33 {
		t.Errorf("expected 33 indicators (32 built-in + 1 feed), got %d", merged.Count())
	}
}
