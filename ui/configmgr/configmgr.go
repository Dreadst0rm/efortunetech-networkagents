package configmgr

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"networksentinel/config"
)

// Snapshot represents a saved configuration snapshot.
type Snapshot struct {
	Name         string    `json:"name"`
	Timestamp    time.Time `json:"timestamp"`
	Config       config.Config
	SnapshotPath string    `json:"snapshot_path"`
}

// ConfigManager handles config save, export, and snapshot operations.
type ConfigManager struct {
	snapshotDir string
}

// NewConfigManager creates a new ConfigManager.
func NewConfigManager(snapshotDir string) *ConfigManager {
	if snapshotDir == "" {
		snapshotDir = "config_snapshots"
	}
	os.MkdirAll(snapshotDir, 0755)
	return &ConfigManager{snapshotDir: snapshotDir}
}

// SaveConfig saves the config to the given file path, returning the written bytes.
func (cm *ConfigManager) SaveConfig(cfg *config.Config, destPath string) ([]byte, error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	dir := filepath.Dir(destPath)
	if dir != "" {
		os.MkdirAll(dir, 0755)
	}
	if err := os.WriteFile(destPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write config: %w", err)
	}
	return data, nil
}

// ExportConfig exports the config to a timestamped file in the given directory.
func (cm *ConfigManager) ExportConfig(cfg *config.Config, destDir string) (string, error) {
	if destDir == "" {
		destDir = "."
	}
	os.MkdirAll(destDir, 0755)
	ts := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("network_sentinel_config_%s.json", ts)
	path := filepath.Join(destDir, filename)
	_, err := cm.SaveConfig(cfg, path)
	if err != nil {
		return "", err
	}
	return path, nil
}

// CreateSnapshot saves a named snapshot of the current config.
func (cm *ConfigManager) CreateSnapshot(cfg *config.Config, name string) (Snapshot, error) {
	if name == "" {
		name = fmt.Sprintf("snapshot_%s", time.Now().Format("20060102_150405"))
	}
	snap := Snapshot{
		Name:      name,
		Timestamp: time.Now(),
		Config:    *cfg,
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return snap, fmt.Errorf("failed to marshal snapshot: %w", err)
	}
	filename := fmt.Sprintf("%s.json", sanitizeFilename(name))
	path := filepath.Join(cm.snapshotDir, filename)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return snap, fmt.Errorf("failed to write snapshot: %w", err)
	}
	snapFilename := filename
	snap.SnapshotPath = snapFilename
	return snap, nil
}

// ListSnapshots returns all saved snapshots.
func (cm *ConfigManager) ListSnapshots() ([]Snapshot, error) {
	entries, err := os.ReadDir(cm.snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot dir: %w", err)
	}
	var snapshots []Snapshot
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			path := filepath.Join(cm.snapshotDir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var snap Snapshot
			if err := json.Unmarshal(data, &snap); err != nil {
				continue
			}
			snap.SnapshotPath = e.Name()
			snapshots = append(snapshots, snap)
		}
	}
	return snapshots, nil
}

// LoadSnapshot loads a snapshot by filename and returns a config from it.
func (cm *ConfigManager) LoadSnapshot(filename string) (*config.Config, error) {
	path := filepath.Join(cm.snapshotDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot: %w", err)
	}
	return &snap.Config, nil
}

// DeleteSnapshot removes a snapshot by filename.
func (cm *ConfigManager) DeleteSnapshot(filename string) error {
	path := filepath.Join(cm.snapshotDir, filename)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete snapshot: %w", err)
	}
	return nil
}

// LoadCurrentConfig reads the current config from the given path.
func LoadCurrentConfig(path string) (*config.Config, error) {
	return config.Load(path)
}

// sanitizeFilename removes characters that are invalid in file names.
func sanitizeFilename(name string) string {
	runes := []rune(name)
	var cleaned []rune
	invalid := map[rune]bool{'<': true, '>': true, ':': true, '"': true, '\\': true, '/': true, '|': true, '?': true, '*': true}
	for _, r := range runes {
		if !invalid[r] {
			cleaned = append(cleaned, r)
		}
	}
	result := string(cleaned)
	if result == "" {
		result = "untitled"
	}
	return result
}
