package systeminfo

import (
	"testing"
)

func TestGetMACAddresses(t *testing.T) {
	macs, err := getMACAddresses()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(macs) == 0 {
		t.Errorf("Expected MAC addresses, got none.")
	}
}

func TestGetHostname(t *testing.T) {
hostname, err := getHostname()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if hostname == "" {
		t.Error("Expected hostname, got empty string")
	}
	t.Logf("Got hostname: %s", hostname)
}
