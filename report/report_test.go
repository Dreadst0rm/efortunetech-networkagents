package report

import (
	"testing"

	"networksentinel/scanner"
)

func TestIsExternal(t *testing.T) {
	cases := []struct {
		addr     string
		expected bool
	}{
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"", false},
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"[::1]", false},
		{"[fe80::1]", false},
	}
	for _, tc := range cases {
		conn := scanner.Connection{RemoteAddr: tc.addr}
		got := IsExternal(conn)
		if got != tc.expected {
			t.Errorf("IsExternal(%q) = %v, want %v", tc.addr, got, tc.expected)
		}
	}
}

func TestIsLocal(t *testing.T) {
	cases := []struct {
		addr     string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		{"", true},
		{"*", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"[::1]", true},
		{"[fe80::1]", true},
	}
	for _, tc := range cases {
		got := IsLocal(tc.addr)
		if got != tc.expected {
			t.Errorf("IsLocal(%q) = %v, want %v", tc.addr, got, tc.expected)
		}
	}
}

func TestIsSuspicious(t *testing.T) {
	cases := []struct {
		addr     string
		expected bool
	}{
		{"192.168.1.1", false},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"", false},
		{"8.8.8.8", true},
	}
	for _, tc := range cases {
		conn := scanner.Connection{RemoteAddr: tc.addr}
		got := IsSuspicious(conn)
		if got != tc.expected {
			t.Errorf("IsSuspicious(%q) = %v, want %v", tc.addr, got, tc.expected)
		}
	}
}

func TestIsSuspiciousProcess(t *testing.T) {
	cases := []struct {
		name     string
		expected bool
	}{
		{"cmd.exe", true},
		{"powershell.exe", true},
		{"certutil.exe", true},
		{"chrome.exe", false},
		{"notepad.exe", false},
	}
	for _, tc := range cases {
		got := IsSuspiciousProcess(tc.name)
		if got != tc.expected {
			t.Errorf("IsSuspiciousProcess(%q) = %v, want %v", tc.name, got, tc.expected)
		}
	}
}

func TestIsSuspiciousPort(t *testing.T) {
	cases := []struct {
		port     int
		expected bool
	}{
		{4444, true},
		{1337, true},
		{8080, true},
		{443, false},
		{80, false},
		{22, false},
	}
	for _, tc := range cases {
		got := isSuspiciousPort(tc.port)
		if got != tc.expected {
			t.Errorf("isSuspiciousPort(%d) = %v, want %v", tc.port, got, tc.expected)
		}
	}
}
