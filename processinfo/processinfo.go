// Package processinfo provides per-PID process security context for privilege escalation detection.
// Platform-specific implementations are in _windows.go, _linux.go, _darwin.go.
package processinfo

import "strings"

// AdminPrivilegeLevel represents the admin privilege level of a process.
type AdminPrivilegeLevel string

const (
	Elevated AdminPrivilegeLevel = "elevated"
	Standard AdminPrivilegeLevel = "standard"
	SYSTEM   AdminPrivilegeLevel = "system"
)

// Info carries per-PID process security context.
type Info struct {
	PID       int
	Name      string
	Username  string
	ExePath   string
	PrivLevel AdminPrivilegeLevel
	IsSystem  bool
	Integrity IntegrityLevel
	Signer    string
	IsSigned  bool
	TokenElev TokenElevationType
}

// TokenElevationType represents the process token elevation state.
type TokenElevationType int

const (
	Full    TokenElevationType = iota // complete elevation
	Limited                           // admin group but limited token
	Default                           // not admin, UAC disabled or standard user
)

func (t TokenElevationType) String() string {
	switch t {
	case Full:
		return "full"
	case Limited:
		return "limited"
	default:
		return "default"
	}
}

// IntegrityLevel represents Windows process integrity.
type IntegrityLevel int

const (
	System IntegrityLevel = iota + 3 // System (highest)
	High                             // High
	Medium                           // Medium
	Low                              // Low
)

func (i IntegrityLevel) String() string {
	switch i {
	case System:
		return "system"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "unknown"
	}
}

// IsPrivEscalation reports whether this process has a privilege escalation risk:
// elevated privilege combined with an unsigned binary and a suspicious execution path.
func (i Info) IsPrivEscalation() bool {
	isElevated := i.PrivLevel == Elevated || i.PrivLevel == SYSTEM
	return isElevated && !i.IsSigned && IsSuspiciousPath(i.ExePath)
}

// suspiciousPathPatterns is populated by each OS-specific init() function.
var suspiciousPathPatterns []string

// IsSuspiciousPath reports whether the given executable path matches any
// known suspicious directory patterns. Patterns are populated per-OS.
func IsSuspiciousPath(exePath string) bool {
	lower := strings.ToLower(exePath)
	for _, p := range suspiciousPathPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
