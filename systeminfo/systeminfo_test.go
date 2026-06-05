package systeminfo

import (
	"runtime"
	"testing"
)

func TestGather(t *testing.T) {
	d, err := Gather()
	if err != nil {
		t.Fatalf("Gather should succeed: %v", err)
	}
	if d.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
	if d.OSPlatform != runtime.GOOS {
		t.Errorf("OSPlatform = %q, want %q", d.OSPlatform, runtime.GOOS)
	}
}

func TestGather_ReturnsDetails(t *testing.T) {
	d, err := Gather()
	if err != nil {
		t.Fatalf("Gather should succeed: %v", err)
	}
	if d == nil {
		t.Fatal("expected non-nil SystemDetails")
	}
	// OSPlatform is always set
	if d.OSPlatform == "" {
		t.Error("expected OSPlatform to be set")
	}
}
