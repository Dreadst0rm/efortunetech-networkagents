package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_baseline.json")

	entries := []Entry{
		{ProcessID: 100, Process: "test.exe", LocalAddr: "192.168.1.1", LocalPort: 80, RemoteAddr: "10.0.0.1", RemotePort: 443, State: "ESTABLISHED"},
		{ProcessID: 200, Process: "test2.exe", LocalAddr: "192.168.1.1", LocalPort: 8080, RemoteAddr: "10.0.0.2", RemotePort: 80, State: "LISTENING"},
	}

	err := Save(filename, "testhost", entries)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	snap, err := Load(filename)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if snap == nil {
		t.Fatal("Load returned nil snapshot")
	}
	if snap.Hostname != "testhost" {
		t.Errorf("expected hostname 'testhost', got %q", snap.Hostname)
	}
	if len(snap.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(snap.Entries))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("__nonexistent__.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(filename, []byte("{invalid}"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	snap, err := Load(filename)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if snap != nil {
		t.Error("expected nil snapshot for invalid JSON")
	}
}

func TestDiff(t *testing.T) {
	prev := &Snapshot{
		Entries: []Entry{
			{ProcessID: 100, Process: "a.exe", LocalAddr: "1.1.1.1", LocalPort: 80, RemoteAddr: "2.2.2.2", RemotePort: 443, State: "ESTABLISHED"},
			{ProcessID: 200, Process: "b.exe", LocalAddr: "1.1.1.1", LocalPort: 8080, RemoteAddr: "3.3.3.3", RemotePort: 80, State: "LISTENING"},
		},
	}

	curr := []Entry{
		{ProcessID: 100, Process: "a.exe", LocalAddr: "1.1.1.1", LocalPort: 80, RemoteAddr: "2.2.2.2", RemotePort: 443, State: "ESTABLISHED"},
		{ProcessID: 300, Process: "c.exe", LocalAddr: "1.1.1.1", LocalPort: 9090, RemoteAddr: "4.4.4.4", RemotePort: 22, State: "ESTABLISHED"},
	}

	diff := Diff(curr, prev)

	if len(diff.New) != 1 {
		t.Errorf("expected 1 new entry, got %d", len(diff.New))
	}
	if len(diff.Gone) != 1 {
		t.Errorf("expected 1 gone entry, got %d", len(diff.Gone))
	}
	if len(diff.Unchanged) != 1 {
		t.Errorf("expected 1 unchanged entry, got %d", len(diff.Unchanged))
	}
}

func TestDiffEmptyPrevious(t *testing.T) {
	prev := &Snapshot{Entries: []Entry{}}
	curr := []Entry{
		{ProcessID: 100, Process: "a.exe", LocalAddr: "1.1.1.1", LocalPort: 80, RemoteAddr: "2.2.2.2", RemotePort: 443, State: "ESTABLISHED"},
	}
	diff := Diff(curr, prev)
	if len(diff.New) != 1 {
		t.Errorf("expected 1 new entry, got %d", len(diff.New))
	}
	if len(diff.Gone) != 0 {
		t.Errorf("expected 0 gone entries, got %d", len(diff.Gone))
	}
}

func TestDiffEmptyCurrent(t *testing.T) {
	prev := &Snapshot{
		Entries: []Entry{
			{ProcessID: 100, Process: "a.exe", LocalAddr: "1.1.1.1", LocalPort: 80, RemoteAddr: "2.2.2.2", RemotePort: 443, State: "ESTABLISHED"},
		},
	}
	diff := Diff(nil, prev)
	if len(diff.New) != 0 {
		t.Errorf("expected 0 new entries, got %d", len(diff.New))
	}
	if len(diff.Gone) != 1 {
		t.Errorf("expected 1 gone entry, got %d", len(diff.Gone))
	}
}
