package threatintel

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadFeed reads C2 indicators from a JSON file and returns a populated ThreatIntelDB.
func LoadFeed(filename string) (*ThreatIntelDB, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read feed file %s: %w", filename, err)
	}

	var iocs []IOC
	if err := json.Unmarshal(data, &iocs); err != nil {
		return nil, fmt.Errorf("parse feed file %s: %w", filename, err)
	}

	db := NewThreatIntelDB()
	db.AddIOCs(iocs)
	return db, nil
}

// GetFeedIOCs returns the raw indicators from a feed file.
func GetFeedIOCs(filename string) ([]IOC, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var iocs []IOC
	if err := json.Unmarshal(data, &iocs); err != nil {
		return nil, err
	}
	return iocs, nil
}

// MergeFeed merges loaded indicators into an existing ThreatIntelDB.
func MergeFeed(db *ThreatIntelDB, iocs []IOC) {
	db.AddIOCs(iocs)
}

// FeedCount returns the number of indicators loaded from a feed file.
func FeedCount(filename string) (int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	var iocs []IOC
	if err := json.Unmarshal(data, &iocs); err != nil {
		return 0, err
	}
	return len(iocs), nil
}
