package processinfo

import (
	"testing"
)

func TestTokenElevationType_String(t *testing.T) {
	tests := []struct {
		te       TokenElevationType
		expected string
	}{
		{Full, "full"},
		{Limited, "limited"},
		{Default, "default"},
		{TokenElevationType(99), "default"},
	}
	for _, tt := range tests {
		result := tt.te.String()
		if result != tt.expected {
			t.Errorf("TokenElevationType(%d).String() = %q, want %q", tt.te, result, tt.expected)
		}
	}
}

func TestIntegrityLevel_String(t *testing.T) {
	tests := []struct {
		il       IntegrityLevel
		expected string
	}{
		{System, "system"},
		{High, "high"},
		{Medium, "medium"},
		{Low, "low"},
		{IntegrityLevel(99), "unknown"},
	}
	for _, tt := range tests {
		result := tt.il.String()
		if result != tt.expected {
			t.Errorf("IntegrityLevel(%d).String() = %q, want %q", tt.il, result, tt.expected)
		}
	}
}

func TestInfo_StructFields(t *testing.T) {
	info := Info{
		PID:       1234,
		Name:      "chrome.exe",
		Username:  "User1",
		ExePath:   "C:\\Program Files\\Google\\Chrome\\chrome.exe",
		PrivLevel: Standard,
		IsSystem:  false,
		Integrity: Medium,
		Signer:    "Google LLC",
		IsSigned:  true,
		TokenElev: Default,
	}
	if info.PID != 1234 {
		t.Errorf("Info.PID = %d, want 1234", info.PID)
	}
	if info.Name != "chrome.exe" {
		t.Errorf("Info.Name = %q, want %q", info.Name, "chrome.exe")
	}
	if info.Username != "User1" {
		t.Errorf("Info.Username = %q, want %q", info.Username, "User1")
	}
	if info.ExePath != "C:\\Program Files\\Google\\Chrome\\chrome.exe" {
		t.Errorf("Info.ExePath = %q, want %q", info.ExePath, "C:\\Program Files\\Google\\Chrome\\chrome.exe")
	}
	if info.PrivLevel != Standard {
		t.Errorf("Info.PrivLevel = %q, want %q", info.PrivLevel, Standard)
	}
	if info.IsSystem != false {
		t.Errorf("Info.IsSystem = %v, want false", info.IsSystem)
	}
	if info.Integrity != Medium {
		t.Errorf("Info.Integrity = %q, want %q", info.Integrity, Medium)
	}
	if info.Signer != "Google LLC" {
		t.Errorf("Info.Signer = %q, want %q", info.Signer, "Google LLC")
	}
	if info.IsSigned != true {
		t.Errorf("Info.IsSigned = %v, want true", info.IsSigned)
	}
	if info.TokenElev != Default {
		t.Errorf("Info.TokenElev = %d, want %d", info.TokenElev, Default)
	}
}

func TestInfo_SystemProcess(t *testing.T) {
	info := Info{
		PID:       4,
		Name:      "System",
		Username:  "SYSTEM",
		ExePath:   "",
		PrivLevel: SYSTEM,
		IsSystem:  true,
		Integrity: System,
		Signer:    "",
		IsSigned:  false,
		TokenElev: Full,
	}
	if info.PrivLevel != SYSTEM {
		t.Errorf("Info.PrivLevel = %q, want %q", info.PrivLevel, SYSTEM)
	}
	if info.IsSystem != true {
		t.Errorf("Info.IsSystem = %v, want true", info.IsSystem)
	}
	if info.Integrity != System {
		t.Errorf("Info.Integrity = %q, want %q", info.Integrity, System)
	}
	if info.TokenElev != Full {
		t.Errorf("Info.TokenElev = %d, want %d", info.TokenElev, Full)
	}
}

func TestInfo_ElevatedUnsigned(t *testing.T) {
	info := Info{
		PID:       5678,
		Name:      "unsigned_app.exe",
		Username:  "User1",
		ExePath:   "C:\\Users\\User1\\AppData\\Local\\Temp\\unsigned_app.exe",
		PrivLevel: Elevated,
		IsSystem:  false,
		Integrity: High,
		Signer:    "",
		IsSigned:  false,
		TokenElev: Limited,
	}
	if info.PrivLevel != Elevated {
		t.Errorf("Info.PrivLevel = %q, want %q", info.PrivLevel, Elevated)
	}
	if info.IsSigned != false {
		t.Errorf("Info.IsSigned = %v, want false", info.IsSigned)
	}
	if info.TokenElev != Limited {
		t.Errorf("Info.TokenElev = %d, want %d", info.TokenElev, Limited)
	}
	if info.Integrity != High {
		t.Errorf("Info.Integrity = %q, want %q", info.Integrity, High)
	}
}

func TestAdminPrivilegeLevel_Constants(t *testing.T) {
	if Elevated != "elevated" {
		t.Errorf("Elevated = %q, want %q", Elevated, "elevated")
	}
	if Standard != "standard" {
		t.Errorf("Standard = %q, want %q", Standard, "standard")
	}
	if SYSTEM != "system" {
		t.Errorf("SYSTEM = %q, want %q", SYSTEM, "system")
	}
}

func TestIntegrityLevel_Constants(t *testing.T) {
	if System != 3 {
		t.Errorf("System = %d, want 3", System)
	}
	if High != 4 {
		t.Errorf("High = %d, want 4", High)
	}
	if Medium != 5 {
		t.Errorf("Medium = %d, want 5", Medium)
	}
	if Low != 6 {
		t.Errorf("Low = %d, want 6", Low)
	}
}

func TestTokenElevation_Constants(t *testing.T) {
	if Full != 0 {
		t.Errorf("Full = %d, want 0", Full)
	}
	if Limited != 1 {
		t.Errorf("Limited = %d, want 1", Limited)
	}
	if Default != 2 {
		t.Errorf("Default = %d, want 2", Default)
	}
}

func TestInfo_StringMethods(t *testing.T) {
	info := Info{
		PID:       1234,
		Name:      "test.exe",
		Username:  "User1",
		ExePath:   "C:\\test.exe",
		PrivLevel: Standard,
		IsSystem:  false,
		Integrity: Medium,
		Signer:    "",
		IsSigned:  false,
		TokenElev: Default,
	}
	if info.Integrity.String() != "medium" {
		t.Errorf("Integrity.String() = %q, want %q", info.Integrity.String(), "medium")
	}
	if info.TokenElev.String() != "default" {
		t.Errorf("TokenElev.String() = %q, want %q", info.TokenElev.String(), "default")
	}
}

func TestInfo_ElevatedSigned(t *testing.T) {
	info := Info{
		PID:       3001,
		Name:      "signed_app.exe",
		Username:  "User1",
		ExePath:   "C:\\Program Files\\Signed\\app.exe",
		PrivLevel: Elevated,
		IsSystem:  false,
		Integrity: High,
		Signer:    "Microsoft Corporation",
		IsSigned:  true,
		TokenElev: Full,
	}
	if info.PrivLevel != Elevated {
		t.Errorf("Info.PrivLevel = %q, want %q", info.PrivLevel, Elevated)
	}
	if info.IsSigned != true {
		t.Errorf("Info.IsSigned = %v, want true", info.IsSigned)
	}
	if info.Signer != "Microsoft Corporation" {
		t.Errorf("Info.Signer = %q, want %q", info.Signer, "Microsoft Corporation")
	}
}

func TestInfo_LowIntegrity(t *testing.T) {
	info := Info{
		PID:       4001,
		Name:      "sandbox.exe",
		Username:  "User1",
		ExePath:   "C:\\Users\\User1\\AppData\\Local\\Temp\\sandbox.exe",
		PrivLevel: Standard,
		IsSystem:  false,
		Integrity: Low,
		Signer:    "",
		IsSigned:  false,
		TokenElev: Default,
	}
	if info.Integrity != Low {
		t.Errorf("Info.Integrity = %q, want %q", info.Integrity, Low)
	}
	if info.PrivLevel != Standard {
		t.Errorf("Info.PrivLevel = %q, want %q", info.PrivLevel, Standard)
	}
}

func TestInfo_SystemSigned(t *testing.T) {
	info := Info{
		PID:       8,
		Name:      "svchost.exe",
		Username:  "SYSTEM",
		ExePath:   "C:\\Windows\\System32\\svchost.exe",
		PrivLevel: SYSTEM,
		IsSystem:  true,
		Integrity: System,
		Signer:    "Microsoft Windows",
		IsSigned:  true,
		TokenElev: Full,
	}
	if info.PrivLevel != SYSTEM {
		t.Errorf("Info.PrivLevel = %q, want %q", info.PrivLevel, SYSTEM)
	}
	if info.IsSystem != true {
		t.Errorf("Info.IsSystem = %v, want true", info.IsSystem)
	}
	if info.Integrity != System {
		t.Errorf("Info.Integrity = %q, want %q", info.Integrity, System)
	}
	if info.IsSigned != true {
		t.Errorf("Info.IsSigned = %v, want true", info.IsSigned)
	}
	if info.Signer != "Microsoft Windows" {
		t.Errorf("Info.Signer = %q, want %q", info.Signer, "Microsoft Windows")
	}
	if info.TokenElev != Full {
		t.Errorf("Info.TokenElev = %d, want %d", info.TokenElev, Full)
	}
}
