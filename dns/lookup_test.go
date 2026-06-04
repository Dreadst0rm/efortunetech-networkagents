package dns

import (
	"testing"
)

func TestLookupDomain_IPv4(t *testing.T) {
	// Localhost reverse lookup should return something
	result := LookupDomain("127.0.0.1")
	t.Logf("LookupDomain(127.0.0.1) = %q", result)
}

func TestLookupDomain_Empty(t *testing.T) {
	result := LookupDomain("")
	if result != "" {
		t.Errorf("expected empty string for empty input, got %q", result)
	}
}

func TestLookupDomain_InvalidIP(t *testing.T) {
	result := LookupDomain("0.0.0.0")
	if result != "" {
		t.Errorf("expected empty string for 0.0.0.0, got %q", result)
	}
}

func TestLookupDomain_Wildcard(t *testing.T) {
	result := LookupDomain("*")
	if result != "" {
		t.Errorf("expected empty string for *, got %q", result)
	}
}

func TestLookupDomain_ExternalIP(t *testing.T) {
	// Try a real external IP — may or may not resolve, but should not panic
	result := LookupDomain("8.8.8.8")
	t.Logf("LookupDomain(8.8.8.8) = %q", result)
}

func TestLookupDomain_ReservedIP(t *testing.T) {
	// 0.0.0.0 should return empty
	result := LookupDomain("0.0.0.0")
	if result != "" {
		t.Errorf("expected empty for 0.0.0.0, got %q", result)
	}
}
