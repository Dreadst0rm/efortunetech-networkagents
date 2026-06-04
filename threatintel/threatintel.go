package threatintel

import (
	"strings"
	"time"
)

// IOC represents a single indicator of compromise from a threat intelligence feed.
type IOC struct {
	Indicator     string    // IP address or domain name
	IndicatorType string    // "ipv4", "domain", "url"
	MalwareFamily string    // e.g., "CobaltStrike", "Metasploit", "LummaStealer"
	FirstSeen     time.Time
	LastSeen      time.Time
	Country       string    // ISO 3166-1 alpha-2
	Confidence    int       // 0-100
	Tags          []string  // e.g., ["c2", "stealer", "rat"]
	Source        string    // e.g., "threatfox", "spamdynamics"
	Status        string    // "active", "inactive"
	Port          int       // C2 port (if applicable)
}

// MatchResult holds the result of an IOC lookup.
type MatchResult struct {
	Indicator string
	IOCs      []IOC
	Count     int
}

// ThreatIntelDB holds the in-memory C2 indicator database.
type ThreatIntelDB struct {
	ipv4   map[string][]IOC
	domain map[string][]IOC
}

// NewThreatIntelDB creates a new threat intelligence database.
func NewThreatIntelDB() *ThreatIntelDB {
	return &ThreatIntelDB{
		ipv4:   make(map[string][]IOC),
		domain: make(map[string][]IOC),
	}
}

// AddIOC adds a single indicator of compromise to the database.
func (db *ThreatIntelDB) AddIOC(ioc IOC) {
	key := strings.ToLower(ioc.Indicator)
	switch ioc.IndicatorType {
	case "ipv4":
		db.ipv4[key] = append(db.ipv4[key], ioc)
	case "domain":
		db.domain[key] = append(db.domain[key], ioc)
	}
}

// AddIOCs adds multiple indicators to the database.
func (db *ThreatIntelDB) AddIOCs(iocs []IOC) {
	for _, ioc := range iocs {
		db.AddIOC(ioc)
	}
}

// LookupIP checks an IP address against the C2 database.
func (db *ThreatIntelDB) LookupIP(ip string) *MatchResult {
	key := strings.ToLower(ip)
	iocs, ok := db.ipv4[key]
	if !ok {
		return nil
	}
	return &MatchResult{
		Indicator: ip,
		IOCs:      iocs,
		Count:     len(iocs),
	}
}

// LookupDomain checks a domain against the C2 database.
func (db *ThreatIntelDB) LookupDomain(domain string) *MatchResult {
	key := strings.ToLower(domain)
	iocs, ok := db.domain[key]
	if !ok {
		return nil
	}
	return &MatchResult{
		Indicator: domain,
		IOCs:      iocs,
		Count:     len(iocs),
	}
}

// LookupConnection checks a connection's remote address against the C2 database.
func (db *ThreatIntelDB) LookupConnection(remoteAddr string) *MatchResult {
	if result := db.LookupIP(remoteAddr); result != nil {
		return result
	}
	return db.LookupDomain(remoteAddr)
}

// Count returns the total number of indicators in the database.
func (db *ThreatIntelDB) Count() int {
	total := 0
	for _, iocs := range db.ipv4 {
		total += len(iocs)
	}
	for _, iocs := range db.domain {
		total += len(iocs)
	}
	return total
}
