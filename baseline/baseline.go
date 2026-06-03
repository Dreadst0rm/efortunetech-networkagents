// Package baseline saves and compares network connection snapshots over time.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Entry represents a single connection in the baseline.
type Entry struct {
	ProcessID  int    `json:"pid"`
	Process    string `json:"process"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
}

// Snapshot is a timestamped collection of baseline entries.
type Snapshot struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	Entries   []Entry   `json:"entries"`
}

// Key returns a unique key for the connection.
func (e Entry) Key() string {
	return fmt.Sprintf("%s:%d", e.RemoteAddr, e.RemotePort)
}

// Save writes the current connections to the baseline file.
func Save(filename string, hostname string, entries []Entry) error {
	snap := Snapshot{
		Timestamp: time.Now(),
		Hostname:  hostname,
		Entries:   entries,
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}
	return os.WriteFile(filename, data, 0644)
}

// Load reads a previous baseline snapshot from disk.
func Load(filename string) (*Snapshot, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal baseline: %w", err)
	}
	return &snap, nil
}

// DiffResult holds the comparison between two snapshots.
type DiffResult struct {
	New         []Entry // in current but not in baseline
	Gone        []Entry // in baseline but not in current
	Unchanged   []Entry // present in both
	BaselineAge time.Duration
}

// Diff compares current entries against a previous baseline snapshot.
func Diff(current []Entry, baseline *Snapshot) DiffResult {
	baselineMap := make(map[string]Entry)
	for _, e := range baseline.Entries {
		baselineMap[e.Key()] = e
	}

	currentMap := make(map[string]Entry)
	for _, e := range current {
		currentMap[e.Key()] = e
	}

	var result DiffResult
	result.BaselineAge = time.Since(baseline.Timestamp)

	// Find new and unchanged
	for k, e := range currentMap {
		if _, ok := baselineMap[k]; ok {
			result.Unchanged = append(result.Unchanged, e)
		} else {
			result.New = append(result.New, e)
		}
	}

	// Find gone
	for k, e := range baselineMap {
		if _, ok := currentMap[k]; !ok {
			result.Gone = append(result.Gone, e)
		}
	}

	return result
}
