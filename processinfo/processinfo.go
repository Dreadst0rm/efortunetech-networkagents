// Package processinfo provides per-PID process security context for privilege escalation detection.
// Platform-specific implementations are in _windows.go, _linux.go, _darwin.go.
package processinfo

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
