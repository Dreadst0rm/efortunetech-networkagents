// Package processinfo provides per-PID process security context for privilege escalation detection.
// Platform-specific implementations are in _windows.go, _linux.go, _darwin.go.
package processinfo

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

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

// IsProcessElevated reports whether the given process info indicates elevated privileges.
func IsProcessElevated(info Info) bool {
	return info.PrivLevel == SYSTEM || info.PrivLevel == Elevated
}

// IsProcessUnsigned reports whether the process has an executable path but no signature.
func IsProcessUnsigned(info Info) bool {
	return info.ExePath != "" && !info.IsSigned
}

// uidToUsername looks up the username for the given UID by reading /etc/passwd.
func uidToUsername(uid int) string {
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return fmt.Sprintf("uid%d", uid)
	}
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			if v, err := strconv.Atoi(fields[2]); err == nil && v == uid {
				return fields[0]
			}
		}
	}
	return fmt.Sprintf("uid%d", uid)
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
