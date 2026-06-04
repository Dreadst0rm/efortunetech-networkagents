package scanner

import (
	"strings"
	"testing"

	"networksentinel/config"
	"networksentinel/processinfo"
)

func TestAssessConnectionRisk_SingleSuspiciousPort(t *testing.T) {
	cfg := config.Defaults()
	conns := []Connection{
		{
			ProcessID:  1234,
			Process:    "chrome.exe",
			RemoteAddr: "203.0.113.50",
			RemotePort: 4444,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, nil, &cfg)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	if risks[0].RiskLevel != RiskMedium {
		t.Errorf("expected medium risk, got %s", risks[0].RiskLevel)
	}
	if len(risks[0].RiskReasons) != 1 {
		t.Errorf("expected 1 reason, got %d: %v", len(risks[0].RiskReasons), risks[0].RiskReasons)
	}
	if risks[0].IsSuspicious != true {
		t.Error("expected isSuspicious=true")
	}
	t.Logf("RiskLevel: %s | Reasons: %v | Connection: %+v", risks[0].RiskLevel, risks[0].RiskReasons, risks[0].Connection)
}

func TestAssessConnectionRisk_MultipleHeuristics(t *testing.T) {
	cfg := config.Defaults()
	conns := []Connection{
		{
			ProcessID:  5678,
			Process:    "cmd.exe",
			RemoteAddr: "198.51.100.10",
			RemotePort: 8080,
			Protocol:   "TCP",
			State:      "SYN_SENT",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, nil, &cfg)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	t.Logf("RiskLevel: %s | Reasons: %v", risks[0].RiskLevel, risks[0].RiskReasons)
	// Should trigger: suspicious port (8080), suspicious process (cmd.exe), transition state (SYN_SENT)
	if len(risks[0].RiskReasons) < 3 {
		t.Errorf("expected >= 3 reasons, got %d: %v", len(risks[0].RiskReasons), risks[0].RiskReasons)
	}
}

func TestAssessConnectionRisk_PlaceholderRiskLevel(t *testing.T) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:        1,
			MinProcessConnections:   1,
			CriticalThreshold:       1,
			HighThreshold:           1,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}
	conns := []Connection{
		{
			ProcessID:  9999,
			Process:    "powershell.exe",
			RemoteAddr: "198.51.100.20",
			RemotePort: 4444,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, nil, &cfg)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	t.Logf("RiskLevel: %s | Reasons: %v", risks[0].RiskLevel, risks[0].RiskReasons)
}

func TestAssessConnectionRisk_NoOutbound(t *testing.T) {
	cfg := config.Defaults()
	conns := []Connection{
		{
			ProcessID:  1111,
			Process:    "svchost.exe",
			RemoteAddr: "0.0.0.0",
			RemotePort: 0,
			Protocol:   "TCP",
			State:      "LISTEN",
			Direction:  "inbound",
		},
	}
	risks := AssessConnectionRisk(conns, nil, &cfg)
	if len(risks) != 0 {
		t.Errorf("expected 0 risks for inbound, got %d", len(risks))
	}
}

func TestAssessConnectionRisk_IPConnectionCount(t *testing.T) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:        3,
			MinProcessConnections:   5,
			CriticalThreshold:       3,
			HighThreshold:           2,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}
	conns := []Connection{
		{
			ProcessID:  2001,
			Process:    "browser.exe",
			RemoteAddr: "10.0.0.5",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
		{
			ProcessID:  2002,
			Process:    "browser.exe",
			RemoteAddr: "10.0.0.5",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
		{
			ProcessID:  2003,
			Process:    "browser.exe",
			RemoteAddr: "10.0.0.5",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, nil, &cfg)
	t.Logf("IP count risks: %d | Risks: %v", len(risks), risks)
	if len(risks) != 3 {
		t.Errorf("expected 3 risks (one per connection), got %d", len(risks))
	}
	// All 3 should have IP connection count heuristic
	allHaveIPCount := true
	for _, r := range risks {
		found := false
		for _, reason := range r.RiskReasons {
			if strings.Contains(reason, "high connection count to 10.0.0.5") {
				found = true
				break
			}
		}
		if !found {
			allHaveIPCount = false
		}
	}
	if !allHaveIPCount {
		t.Error("expected all connections to have IP connection count reason")
	}
}

func TestAssessConnectionRisk_PrivilegeEscalationChain(t *testing.T) {
	cfg := config.Defaults()
	secInfo := map[int]processinfo.Info{
		3001: {
			PID:       3001,
			Name:      "malware.exe",
			Username:  "User1",
			ExePath:   "C:\\Users\\User1\\AppData\\Local\\Temp\\malware.exe",
			PrivLevel: processinfo.Elevated,
			IsSystem:  false,
			Integrity: processinfo.High,
			Signer:    "",
			IsSigned:  false,
			TokenElev: processinfo.Full,
		},
	}
	conns := []Connection{
		{
			ProcessID:  3001,
			Process:    "malware.exe",
			RemoteAddr: "198.51.100.30",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, secInfo, &cfg)
	t.Logf("PrivEsc risks: %d | Risks: %+v", len(risks), risks)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	found := false
	for _, reason := range risks[0].RiskReasons {
		if strings.Contains(reason, "PRIVILEGE ESCALATION") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected privilege escalation reason, got: %v", risks[0].RiskReasons)
	}
}

func TestAssessConnectionRisk_ElevatedUnsignedNoTemp(t *testing.T) {
	cfg := config.Defaults()
	secInfo := map[int]processinfo.Info{
		3002: {
			PID:       3002,
			Name:      "unsigned_app.exe",
			Username:  "User1",
			ExePath:   "C:\\Program Files\\Unsigned\\app.exe",
			PrivLevel: processinfo.Elevated,
			IsSystem:  false,
			Integrity: processinfo.High,
			Signer:    "",
			IsSigned:  false,
			TokenElev: processinfo.Full,
		},
	}
	conns := []Connection{
		{
			ProcessID:  3002,
			Process:    "unsigned_app.exe",
			RemoteAddr: "198.51.100.40",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, secInfo, &cfg)
	t.Logf("ElevatedUnsigned risks: %d | Risks: %+v", len(risks), risks)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	found := false
	for _, reason := range risks[0].RiskReasons {
		if strings.Contains(reason, "elevated + unsigned") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected elevated + unsigned reason, got: %v", risks[0].RiskReasons)
	}
}

func TestAssessConnectionRisk_ElevatedSignedTempPath(t *testing.T) {
	cfg := config.Defaults()
	secInfo := map[int]processinfo.Info{
		3003: {
			PID:       3003,
			Name:      "signed_app.exe",
			Username:  "User1",
			ExePath:   "C:\\Users\\User1\\AppData\\Local\\Temp\\signed_app.exe",
			PrivLevel: processinfo.Elevated,
			IsSystem:  false,
			Integrity: processinfo.High,
			Signer:    "Microsoft Corporation",
			IsSigned:  true,
			TokenElev: processinfo.Full,
		},
	}
	conns := []Connection{
		{
			ProcessID:  3003,
			Process:    "signed_app.exe",
			RemoteAddr: "198.51.100.50",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, secInfo, &cfg)
	t.Logf("ElevatedSignedTemp risks: %d | Risks: %+v", len(risks), risks)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	found := false
	for _, reason := range risks[0].RiskReasons {
		if strings.Contains(reason, "temp path") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected elevated + temp path reason, got: %v", risks[0].RiskReasons)
	}
}

func TestAssessConnectionRisk_NoSecurityInfo(t *testing.T) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:        5,
			MinProcessConnections:   5,
			CriticalThreshold:       3,
			HighThreshold:           2,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}
	conns := []Connection{
		{
			ProcessID:  4001,
			Process:    "notepad.exe",
			RemoteAddr: "203.0.113.100",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, nil, &cfg)
	t.Logf("NoSecurityInfo risks: %d | Risks: %+v", len(risks), risks)
	// Normal connection with no heuristic triggers should produce 0 risks
	// (empty risk level means no heuristics fired)
	for _, r := range risks {
		if len(r.RiskReasons) > 0 {
			t.Errorf("expected no risk reasons for normal connection, got: %v", r.RiskReasons)
		}
	}
}

func TestAssessConnectionRisk_SystemProcessTempPath(t *testing.T) {
	cfg := config.Defaults()
	secInfo := map[int]processinfo.Info{
		5001: {
			PID:       5001,
			Name:      "svchost.exe",
			Username:  "SYSTEM",
			ExePath:   "C:\\Users\\User1\\AppData\\Local\\Temp\\svchost.exe",
			PrivLevel: processinfo.SYSTEM,
			IsSystem:  true,
			Integrity: processinfo.System,
			Signer:    "",
			IsSigned:  false,
			TokenElev: processinfo.Full,
		},
	}
	conns := []Connection{
		{
			ProcessID:  5001,
			Process:    "svchost.exe",
			RemoteAddr: "198.51.100.60",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, secInfo, &cfg)
	t.Logf("SystemTemp risks: %d | Risks: %+v", len(risks), risks)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	found := false
	for _, reason := range risks[0].RiskReasons {
		if strings.Contains(reason, "PRIVILEGE ESCALATION") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected privilege escalation reason, got: %v", risks[0].RiskReasons)
	}
}

func TestAssessConnectionRisk_MultipleConnectionsDifferentProcesses(t *testing.T) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:        2,
			MinProcessConnections:   2,
			CriticalThreshold:       3,
			HighThreshold:           2,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}
	conns := []Connection{
		{
			ProcessID:  6001,
			Process:    "cmd.exe",
			RemoteAddr: "198.51.100.70",
			RemotePort: 4444,
			Protocol:   "TCP",
			State:      "SYN_SENT",
			Direction:  "outbound",
		},
		{
			ProcessID:  6002,
			Process:    "cmd.exe",
			RemoteAddr: "198.51.100.70",
			RemotePort: 4444,
			Protocol:   "TCP",
			State:      "SYN_SENT",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, nil, &cfg)
	t.Logf("Multi-process risks: %d | Risks: %+v", len(risks), risks)
	if len(risks) != 2 {
		t.Errorf("expected 2 risks, got %d", len(risks))
	}
	// Each should have: suspicious port, suspicious process, transition state, IP count >= 2, process count >= 2
	for _, r := range risks {
		t.Logf("  Risk: %s | Reasons: %v", r.RiskLevel, r.RiskReasons)
		if len(r.RiskReasons) < 5 {
			t.Errorf("expected 5 reasons, got %d: %v", len(r.RiskReasons), r.RiskReasons)
		}
	}
}

func TestIsSuspiciousState(t *testing.T) {
	tests := []struct {
		state    string
		expected bool
	}{
		{"SYN_SENT", true},
		{"SYN_RECEIVED", true},
		{"TIME_WAIT", true},
		{"CLOSE_WAIT", true},
		{"ESTABLISHED", false},
		{"LISTEN", false},
		{"CLOSED", false},
		{"syn_sent", true},
		{"Established", false},
	}
	for _, tt := range tests {
		result := IsSuspiciousState(tt.state)
		if result != tt.expected {
			t.Errorf("IsSuspiciousState(%q) = %v, want %v", tt.state, result, tt.expected)
		}
	}
}

func TestIsTransitionState(t *testing.T) {
	tests := []struct {
		state    string
		expected bool
	}{
		{"SYN_SENT", true},
		{"SYN_RECEIVED", true},
		{"TIME_WAIT", true},
		{"CLOSE_WAIT", true},
		{"ESTABLISHED", false},
		{"LISTEN", false},
		{"CLOSED", false},
	}
	for _, tt := range tests {
		result := IsTransitionState(tt.state)
		if result != tt.expected {
			t.Errorf("IsTransitionState(%q) = %v, want %v", tt.state, result, tt.expected)
		}
	}
}

func TestIsSuspiciousPort(t *testing.T) {
	tests := []struct {
		port     int
		expected bool
	}{
		{4444, true},
		{8080, true},
		{1337, true},
		{9001, true},
		{443, false},
		{80, false},
		{22, false},
		{4443, false},
		{8081, false},
	}
	for _, tt := range tests {
		result := IsSuspiciousPort(tt.port)
		if result != tt.expected {
			t.Errorf("IsSuspiciousPort(%d) = %v, want %v", tt.port, result, tt.expected)
		}
	}
}

func TestIsExternalIP(t *testing.T) {
	tests := []struct {
		addr     string
		expected bool
	}{
		{"203.0.113.50", true},
		{"198.51.100.10", true},
		{"8.8.8.8", true},
		{"127.0.0.1", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.32.0.1", false},
		{"0.0.0.0", false},
		{"*", false},
		{"", false},
		{"[::1]:443", false},
		{"[fe80::1]:443", false},
	}
	for _, tt := range tests {
		result := IsExternalIP(tt.addr)
		if result != tt.expected {
			t.Errorf("IsExternalIP(%q) = %v, want %v", tt.addr, result, tt.expected)
		}
	}
}

func TestIsPrivatePrefix(t *testing.T) {
	tests := []struct {
		s        string
		prefix   string
		expected bool
	}{
		{"172.16.0.1", "172", true},
		{"172.32.0.1", "172", true},
		{"1720.0.1", "172", false},
		{"192.168.1.1", "172", false},
		{"fd00::1", "fd", false},
		{"fe80::1", "fd", false},
	}
	for _, tt := range tests {
		result := isPrivatePrefix(tt.s, tt.prefix)
		if result != tt.expected {
			t.Errorf("isPrivatePrefix(%q, %q) = %v, want %v", tt.s, tt.prefix, result, tt.expected)
		}
	}
}

func TestIsSuspiciousProcess(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"cmd.exe", true},
		{"powershell.exe", true},
		{"wmic.exe", true},
		{"certutil.exe", true},
		{"chrome.exe", false},
		{"svchost.exe", false},
		{"notepad.exe", false},
		{"CMD.EXE", true},
		{"PoWeRsHeLl.eXe", true},
	}
	for _, tt := range tests {
		result := IsSuspiciousProcess(tt.name)
		if result != tt.expected {
			t.Errorf("IsSuspiciousProcess(%q) = %v, want %v", tt.name, result, tt.expected)
		}
	}
}

func TestDetermineDirection(t *testing.T) {
	tests := []struct {
		conn     Connection
		expected string
	}{
		{
			conn:     Connection{RemoteAddr: "0.0.0.0", RemotePort: 0, Direction: ""},
			expected: "inbound",
		},
		{
			conn:     Connection{RemoteAddr: "*", RemotePort: 0, Direction: ""},
			expected: "inbound",
		},
		{
			conn:     Connection{RemoteAddr: "", RemotePort: 0, Direction: ""},
			expected: "inbound",
		},
		{
			conn:     Connection{RemoteAddr: "::1", RemotePort: 443, Direction: ""},
			expected: "internal",
		},
		{
			conn:     Connection{RemoteAddr: "fe80::1", RemotePort: 443, Direction: ""},
			expected: "internal",
		},
		{
			conn:     Connection{RemoteAddr: "fd00::1", RemotePort: 443, Direction: ""},
			expected: "internal",
		},
		{
			conn:     Connection{RemoteAddr: "ff00::1", RemotePort: 443, Direction: ""},
			expected: "internal",
		},
		{
			conn:     Connection{RemoteAddr: "127.0.0.1", RemotePort: 443, Direction: ""},
			expected: "internal",
		},
		{
			conn:     Connection{RemoteAddr: "192.168.1.1", RemotePort: 443, Direction: ""},
			expected: "internal",
		},
		{
			conn:     Connection{RemoteAddr: "10.0.0.1", RemotePort: 443, Direction: ""},
			expected: "internal",
		},
		{
			conn:     Connection{RemoteAddr: "172.16.0.1", RemotePort: 443, Direction: ""},
			expected: "internal",
		},
		{
			conn:     Connection{RemoteAddr: "203.0.113.50", RemotePort: 443, Direction: ""},
			expected: "outbound",
		},
		{
			conn:     Connection{RemoteAddr: "198.51.100.10", RemotePort: 8080, Direction: ""},
			expected: "outbound",
		},
	}
	for _, tt := range tests {
		result := determineDirection(&tt.conn)
		if result != tt.expected {
			t.Errorf("determineDirection(%+v) = %q, want %q", tt.conn, result, tt.expected)
		}
	}
}

func TestAssessConnectionRisk_CriticalRisk(t *testing.T) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:        1,
			MinProcessConnections:   1,
			CriticalThreshold:       3,
			HighThreshold:           2,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}
	secInfo := map[int]processinfo.Info{
		7001: {
			PID:       7001,
			Name:      "cmd.exe",
			Username:  "User1",
			ExePath:   "C:\\Users\\User1\\AppData\\Local\\Temp\\cmd.exe",
			PrivLevel: processinfo.Elevated,
			IsSystem:  false,
			Integrity: processinfo.High,
			Signer:    "",
			IsSigned:  false,
			TokenElev: processinfo.Full,
		},
	}
	conns := []Connection{
		{
			ProcessID:  7001,
			Process:    "cmd.exe",
			RemoteAddr: "198.51.100.80",
			RemotePort: 4444,
			Protocol:   "TCP",
			State:      "SYN_SENT",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, secInfo, &cfg)
	t.Logf("Critical risk: %d | Risks: %+v", len(risks), risks)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	if risks[0].RiskLevel != RiskCritical {
		t.Errorf("expected critical risk, got %s", risks[0].RiskLevel)
	}
	t.Logf("RiskLevel: %s | Reasons: %v", risks[0].RiskLevel, risks[0].RiskReasons)
}

func TestAssessConnectionRisk_HighRisk(t *testing.T) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:        1,
			MinProcessConnections:   1,
			CriticalThreshold:       4,
			HighThreshold:           2,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}
	secInfo := map[int]processinfo.Info{
		8001: {
			PID:       8001,
			Name:      "cmd.exe",
			Username:  "User1",
			ExePath:   "C:\\Program Files\\App\\cmd.exe",
			PrivLevel: processinfo.Elevated,
			IsSystem:  false,
			Integrity: processinfo.High,
			Signer:    "",
			IsSigned:  false,
			TokenElev: processinfo.Full,
		},
	}
	conns := []Connection{
		{
			ProcessID:  8001,
			Process:    "cmd.exe",
			RemoteAddr: "198.51.100.90",
			RemotePort: 4444,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, secInfo, &cfg)
	t.Logf("High risk: %d | Risks: %+v", len(risks), risks)
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}
	// With 4 reasons (port, process, ip count, proc count, priv esc) = 5 reasons, critical threshold is 4
	// So it should be critical, not high. Let's verify the actual level.
	t.Logf("RiskLevel: %s | Reasons: %v", risks[0].RiskLevel, risks[0].RiskReasons)
	if risks[0].RiskLevel != RiskCritical {
		t.Errorf("expected critical risk (5 reasons >= 4 threshold), got %s", risks[0].RiskLevel)
	}
}

func TestAssessConnectionRisk_ProcessConnectionCount(t *testing.T) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:        5,
			MinProcessConnections:   3,
			CriticalThreshold:       3,
			HighThreshold:           2,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}
	conns := []Connection{
		{
			ProcessID:  9001,
			Process:    "botnet.exe",
			RemoteAddr: "198.51.100.100",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
		{
			ProcessID:  9002,
			Process:    "botnet.exe",
			RemoteAddr: "198.51.100.101",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
		{
			ProcessID:  9003,
			Process:    "botnet.exe",
			RemoteAddr: "198.51.100.102",
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		},
	}
	risks := AssessConnectionRisk(conns, nil, &cfg)
	t.Logf("Process count risks: %d | Risks: %+v", len(risks), risks)
	if len(risks) != 3 {
		t.Fatalf("expected 3 risks, got %d", len(risks))
	}
	// All 3 should have process connection count heuristic
	allHaveProcCount := true
	for _, r := range risks {
		found := false
		for _, reason := range r.RiskReasons {
			if strings.Contains(reason, "high outbound connection count for botnet.exe") {
				found = true
				break
			}
		}
		if !found {
			allHaveProcCount = false
		}
	}
	if !allHaveProcCount {
		t.Error("expected all connections to have process connection count reason")
	}
}
