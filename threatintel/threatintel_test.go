package threatintel

import (
	"testing"
	"time"
)

func TestNewThreatIntelDB(t *testing.T) {
	db := NewThreatIntelDB()
	if db == nil {
		t.Fatal("NewThreatIntelDB returned nil")
	}
	if db.Count() != 0 {
		t.Errorf("expected 0 indicators, got %d", db.Count())
	}
}

func TestAddIOC_IP(t *testing.T) {
	db := NewThreatIntelDB()
	ioc := IOC{
		Indicator:     "185.141.22.206",
		IndicatorType: "ipv4",
		MalwareFamily: "CobaltStrike",
		Country:       "RU",
		Confidence:    95,
	}
	db.AddIOC(ioc)
	if db.Count() != 1 {
		t.Errorf("expected 1 indicator, got %d", db.Count())
	}
}

func TestAddIOC_Domain(t *testing.T) {
	db := NewThreatIntelDB()
	ioc := IOC{
		Indicator:     "secure-login-verify.tk",
		IndicatorType: "domain",
		MalwareFamily: "Phishing",
		Country:       "RU",
		Confidence:    92,
	}
	db.AddIOC(ioc)
	if db.Count() != 1 {
		t.Errorf("expected 1 indicator, got %d", db.Count())
	}
}

func TestAddIOCs_Multiple(t *testing.T) {
	db := NewThreatIntelDB()
	iocs := []IOC{
		{Indicator: "185.141.22.206", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike"},
		{Indicator: "194.26.199.178", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike"},
		{Indicator: "secure-login-verify.tk", IndicatorType: "domain", MalwareFamily: "Phishing"},
	}
	db.AddIOCs(iocs)
	if db.Count() != 3 {
		t.Errorf("expected 3 indicators, got %d", db.Count())
	}
}

func TestLookupIP_Match(t *testing.T) {
	db := NewThreatIntelDB()
	db.AddIOCs(KnownC2IPs)
	result := db.LookupIP("185.141.22.206")
	if result == nil {
		t.Fatal("expected match for known C2 IP")
	}
	if result.Count == 0 {
		t.Error("expected non-zero match count")
	}
	if result.IOCs[0].MalwareFamily != "CobaltStrike" {
		t.Errorf("expected CobaltStrike, got %s", result.IOCs[0].MalwareFamily)
	}
}

func TestLookupIP_NoMatch(t *testing.T) {
	db := NewThreatIntelDB()
	db.AddIOCs(KnownC2IPs)
	result := db.LookupIP("8.8.8.8")
	if result != nil {
		t.Errorf("expected nil for unknown IP, got %+v", result)
	}
}

func TestLookupDomain_Match(t *testing.T) {
	db := NewThreatIntelDB()
	db.AddIOCs(KnownC2IPs)
	result := db.LookupDomain("secure-login-verify.tk")
	if result == nil {
		t.Fatal("expected match for known phishing domain")
	}
	if result.Count == 0 {
		t.Error("expected non-zero match count")
	}
	if result.IOCs[0].MalwareFamily != "Phishing" {
		t.Errorf("expected Phishing, got %s", result.IOCs[0].MalwareFamily)
	}
}

func TestLookupDomain_CaseInsensitive(t *testing.T) {
	db := NewThreatIntelDB()
	db.AddIOCs(KnownC2IPs)
	result := db.LookupDomain("SECURE-LOGIN-VERIFY.TK")
	if result == nil {
		t.Fatal("expected case-insensitive match")
	}
}

func TestLookupConnection_IP(t *testing.T) {
	db := NewThreatIntelDB()
	db.AddIOCs(KnownC2IPs)
	result := db.LookupConnection("185.141.22.206")
	if result == nil {
		t.Fatal("expected IP match")
	}
}

func TestLookupConnection_Domain(t *testing.T) {
	db := NewThreatIntelDB()
	db.AddIOCs(KnownC2IPs)
	result := db.LookupConnection("secure-login-verify.tk")
	if result == nil {
		t.Fatal("expected domain match")
	}
}

func TestLookupConnection_NoMatch(t *testing.T) {
	db := NewThreatIntelDB()
	db.AddIOCs(KnownC2IPs)
	result := db.LookupConnection("192.168.1.1")
	if result != nil {
		t.Errorf("expected nil for local IP, got %+v", result)
	}
}

func TestIOC_StructFields(t *testing.T) {
	ioc := IOC{
		Indicator:     "185.141.22.206",
		IndicatorType: "ipv4",
		MalwareFamily: "CobaltStrike",
		FirstSeen:     time.Date(2023, 1, 15, 0, 0, 0, 0, time.UTC),
		LastSeen:      time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		Country:       "RU",
		Confidence:    95,
		Tags:          []string{"c2", "cobalt-strike"},
		Source:        "threatfox",
		Status:        "active",
		Port:          443,
	}
	if ioc.Indicator != "185.141.22.206" {
		t.Errorf("Indicator = %s, want 185.141.22.206", ioc.Indicator)
	}
	if ioc.MalwareFamily != "CobaltStrike" {
		t.Errorf("MalwareFamily = %s, want CobaltStrike", ioc.MalwareFamily)
	}
	if ioc.Confidence != 95 {
		t.Errorf("Confidence = %d, want 95", ioc.Confidence)
	}
	if ioc.Country != "RU" {
		t.Errorf("Country = %s, want RU", ioc.Country)
	}
	if len(ioc.Tags) != 2 {
		t.Errorf("Tags length = %d, want 2", len(ioc.Tags))
	}
}

func TestKnownC2IPs_Count(t *testing.T) {
	if len(KnownC2IPs) == 0 {
		t.Fatal("KnownC2IPs is empty")
	}
	if len(KnownC2IPs) < 25 {
		t.Errorf("KnownC2IPs has only %d entries, expected at least 25", len(KnownC2IPs))
	}

	ipv4Count := 0
	domainCount := 0
	for _, ioc := range KnownC2IPs {
		switch ioc.IndicatorType {
		case "ipv4":
			ipv4Count++
		case "domain":
			domainCount++
		}
	}
	t.Logf("KnownC2IPs: %d IPv4, %d domain, %d total", ipv4Count, domainCount, len(KnownC2IPs))

	if ipv4Count == 0 {
		t.Error("no IPv4 indicators in KnownC2IPs")
	}
	if domainCount == 0 {
		t.Error("no domain indicators in KnownC2IPs")
	}
}

func TestThreatIntelDB_Deduplication(t *testing.T) {
	db := NewThreatIntelDB()
	db.AddIOC(IOC{Indicator: "185.141.22.206", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike"})
	db.AddIOC(IOC{Indicator: "185.141.22.206", IndicatorType: "ipv4", MalwareFamily: "Metasploit"})
	result := db.LookupIP("185.141.22.206")
	if result == nil || result.Count != 2 {
		t.Errorf("expected 2 duplicates for same IP, got %d", result.Count)
	}
}
