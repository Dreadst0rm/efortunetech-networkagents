package scanner

import (
	"testing"

	"networksentinel/config"
	"networksentinel/processinfo"
	"networksentinel/threatintel"
)

// BenchmarkAssessConnectionRisk measures the performance of the risk assessment
// with varying numbers of connections.
func BenchmarkAssessConnectionRisk(b *testing.B) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:      5,
			MinProcessConnections: 5,
			CriticalThreshold:     3,
			HighThreshold:         2,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}

	// Build a realistic set of connections (simulating ~200 connections)
	conns := make([]Connection, 0, 200)
	for i := 0; i < 50; i++ {
		conns = append(conns, Connection{
			ProcessID:  1000 + i,
			Process:    "chrome.exe",
			LocalAddr:  "192.168.1." + string(rune('0'+i%256)),
			LocalPort:  49152 + i,
			RemoteAddr: "203.0.113." + string(rune('1'+i%256)),
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		})
	}
	for i := 0; i < 50; i++ {
		conns = append(conns, Connection{
			ProcessID:  2000 + i,
			Process:    "cmd.exe",
			LocalAddr:  "192.168.1." + string(rune('0'+i%256)),
			LocalPort:  49152 + i,
			RemoteAddr: "198.51.100." + string(rune('1'+i%256)),
			RemotePort: 4444,
			Protocol:   "TCP",
			State:      "SYN_SENT",
			Direction:  "outbound",
		})
	}
	for i := 0; i < 100; i++ {
		conns = append(conns, Connection{
			ProcessID:  3000 + i,
			Process:    "svchost.exe",
			LocalAddr:  "192.168.1." + string(rune('0'+i%256)),
			LocalPort:  49152 + i,
			RemoteAddr: "10.0.0." + string(rune('1'+i%256)),
			RemotePort: 80,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		})
	}

	secInfo := map[int]processinfo.Info{
		1000: {
			PID: 1000, Name: "chrome.exe", ExePath: "C:\\Program Files\\Chrome\\chrome.exe",
			PrivLevel: processinfo.Standard, IsSigned: true,
		},
		2000: {
			PID: 2000, Name: "cmd.exe", ExePath: "C:\\Users\\User1\\AppData\\Local\\Temp\\cmd.exe",
			PrivLevel: processinfo.Elevated, IsSigned: false,
		},
		3000: {
			PID: 3000, Name: "svchost.exe", ExePath: "C:\\Windows\\System32\\svchost.exe",
			PrivLevel: processinfo.SYSTEM, IsSigned: true,
		},
	}

	b.Run("200_conns", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			risks := AssessConnectionRisk(conns, secInfo, &cfg)
			if len(risks) == 0 {
				b.Fatal("no risks")
			}
		}
	})

	b.Run("50_conns", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			risks := AssessConnectionRisk(conns[:50], secInfo, &cfg)
			_ = risks
		}
	})

	b.Run("10_conns", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			risks := AssessConnectionRisk(conns[:10], secInfo, &cfg)
			_ = risks
		}
	})
}

// BenchmarkIsWhitelistedIP measures whitelist lookup performance.
func BenchmarkIsWhitelistedIP(b *testing.B) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:      5,
			MinProcessConnections: 5,
			CriticalThreshold:     3,
			HighThreshold:         2,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
		Whitelist: []config.WhitelistedIP{
			{IP: "8.8.8.8", Comment: "Google DNS"},
			{IP: "1.1.1.1", Comment: "Cloudflare"},
			{IP: "203.0.113.1", Comment: "Internal gateway"},
			{IP: "198.51.100.1", Comment: "Test network"},
			{IP: "10.0.0.1", Comment: "Router"},
			{IP: "172.16.0.1", Comment: "Internal"},
			{IP: "13.107.42.14", Comment: "Microsoft"},
			{IP: "52.96.166.242", Comment: "AWS"},
			{IP: "151.101.1.69", Comment: "Reddit"},
			{IP: "140.82.121.4", Comment: "GitHub"},
			{IP: "31.13.120.36", Comment: "Facebook"},
			{IP: "157.242.42.138", Comment: "Twitter"},
			{IP: "91.108.4.136", Comment: "Telegram"},
			{IP: "104.244.42.1", Comment: "Twitter alt"},
			{IP: "199.232.69.194", Comment: "CDN"},
			{IP: "142.250.189.45", Comment: "Google alt"},
			{IP: "23.210.242.240", Comment: "CDN2"},
			{IP: "185.199.108.153", Comment: "GitHub Pages"},
			{IP: "151.101.65.69", Comment: "Reddit alt"},
			{IP: "104.16.85.20", Comment: "Cloudflare alt"},
		},
	}

	b.Run("whitelisted_ip", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = cfg.IsWhitelistedIP("8.8.8.8")
		}
	})

	b.Run("non_whitelisted_ip", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = cfg.IsWhitelistedIP("1.2.3.4")
		}
	})
}

// BenchmarkIsSuspiciousProcess measures the suspicious process check performance.
func BenchmarkIsSuspiciousProcess(b *testing.B) {
	b.Run("suspicious", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = IsSuspiciousProcess("cmd.exe")
		}
	})

	b.Run("not_suspicious", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = IsSuspiciousProcess("chrome.exe")
		}
	})
}

// BenchmarkIsPrivateIP measures IP classification performance.
func BenchmarkIsPrivateIP(b *testing.B) {
	testCases := []string{
		"203.0.113.50",
		"198.51.100.10",
		"8.8.8.8",
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"172.32.0.1",
		"0.0.0.0",
		"*",
		"",
		"[::1]:443",
		"[fe80::1]:443",
		"fe80::1",
		"fd00::1",
		"ff00::1",
		"::1",
		"::",
	}

	b.Run("IsPrivateIP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, tc := range testCases {
				_ = IsPrivateIP(tc)
			}
		}
	})
}

// BenchmarkThreatIntelDB measures threat intel lookup performance.
func BenchmarkThreatIntelDB(b *testing.B) {
	db := threatintel.NewThreatIntelDB()
	db.AddIOCs(threatintel.KnownC2IPs)

	b.Run("LookupIP_hit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = db.LookupIP("185.141.22.206")
		}
	})

	b.Run("LookupIP_miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = db.LookupIP("1.2.3.4")
		}
	})
}

// BenchmarkScanAllConnectionRiskPipeline measures the full risk assessment pipeline.
func BenchmarkScanAllConnectionRiskPipeline(b *testing.B) {
	cfg := config.Config{
		Thresholds: config.Thresholds{
			MinIPConnections:      5,
			MinProcessConnections: 5,
			CriticalThreshold:     3,
			HighThreshold:         2,
		},
		Excluded: config.Excluded{
			PIDs:      []int{},
			Processes: []string{},
		},
	}

	// Build 500 connections (larger realistic scenario)
	conns := make([]Connection, 0, 500)
	for i := 0; i < 150; i++ {
		conns = append(conns, Connection{
			ProcessID:  1000 + i,
			Process:    "chrome.exe",
			LocalAddr:  "192.168.1." + string(rune('0'+i%256)),
			LocalPort:  49152 + i,
			RemoteAddr: "203.0.113." + string(rune('1'+i%256)),
			RemotePort: 443,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		})
	}
	for i := 0; i < 150; i++ {
		conns = append(conns, Connection{
			ProcessID:  2000 + i,
			Process:    "powershell.exe",
			LocalAddr:  "192.168.1." + string(rune('0'+i%256)),
			LocalPort:  49152 + i,
			RemoteAddr: "198.51.100." + string(rune('1'+i%256)),
			RemotePort: 4444,
			Protocol:   "TCP",
			State:      "SYN_SENT",
			Direction:  "outbound",
		})
	}
	for i := 0; i < 200; i++ {
		conns = append(conns, Connection{
			ProcessID:  3000 + i,
			Process:    "svchost.exe",
			LocalAddr:  "192.168.1." + string(rune('0'+i%256)),
			LocalPort:  49152 + i,
			RemoteAddr: "10.0.0." + string(rune('1'+i%256)),
			RemotePort: 80,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
			Direction:  "outbound",
		})
	}

	secInfo := map[int]processinfo.Info{
		1000: {
			PID: 1000, Name: "chrome.exe", ExePath: "C:\\Program Files\\Chrome\\chrome.exe",
			PrivLevel: processinfo.Standard, IsSigned: true,
		},
		2000: {
			PID: 2000, Name: "powershell.exe", ExePath: "C:\\Users\\User1\\AppData\\Local\\Temp\\powershell.exe",
			PrivLevel: processinfo.Elevated, IsSigned: false,
		},
		3000: {
			PID: 3000, Name: "svchost.exe", ExePath: "C:\\Windows\\System32\\svchost.exe",
			PrivLevel: processinfo.SYSTEM, IsSigned: true,
		},
	}

	tiDB := threatintel.NewThreatIntelDB()
	tiDB.AddIOCs(threatintel.KnownC2IPs)

	b.Run("500_conns_full_pipeline", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			risks := AssessConnectionRisk(conns, secInfo, &cfg)
			risks = AssessConnectionRiskWithThreatIntel(conns, secInfo, &cfg, tiDB)
			if len(risks) == 0 {
				b.Fatal("no risks")
			}
		}
	})
}

// BenchmarkDetermineDirection measures direction classification.
func BenchmarkDetermineDirection(b *testing.B) {
	testCases := []Connection{
		{RemoteAddr: "0.0.0.0", RemotePort: 0, Direction: ""},
		{RemoteAddr: "*", RemotePort: 0, Direction: ""},
		{RemoteAddr: "", RemotePort: 0, Direction: ""},
		{RemoteAddr: "::1", RemotePort: 443, Direction: ""},
		{RemoteAddr: "fe80::1", RemotePort: 443, Direction: ""},
		{RemoteAddr: "fd00::1", RemotePort: 443, Direction: ""},
		{RemoteAddr: "ff00::1", RemotePort: 443, Direction: ""},
		{RemoteAddr: "127.0.0.1", RemotePort: 443, Direction: ""},
		{RemoteAddr: "192.168.1.1", RemotePort: 443, Direction: ""},
		{RemoteAddr: "10.0.0.1", RemotePort: 443, Direction: ""},
		{RemoteAddr: "172.16.0.1", RemotePort: 443, Direction: ""},
		{RemoteAddr: "203.0.113.50", RemotePort: 443, Direction: ""},
		{RemoteAddr: "198.51.100.10", RemotePort: 8080, Direction: ""},
	}

	b.Run("determineDirection", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, tc := range testCases {
				_ = determineDirection(&tc)
			}
		}
	})
}

// BenchmarkIsTransitionState measures TCP state classification.
func BenchmarkIsTransitionState(b *testing.B) {
	states := []string{"SYN_SENT", "SYN_RECEIVED", "TIME_WAIT", "CLOSE_WAIT", "ESTABLISHED", "LISTEN", "CLOSED"}

	b.Run("IsTransitionState", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, s := range states {
				_ = IsTransitionState(s)
			}
		}
	})
}

// BenchmarkIsSuspiciousPort measures port classification.
func BenchmarkIsSuspiciousPort(b *testing.B) {
	ports := []int{4444, 8080, 1337, 9001, 443, 80, 22, 4443, 8081, 2525, 4242}

	b.Run("IsSuspiciousPort", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, p := range ports {
				_ = IsSuspiciousPort(p)
			}
		}
	})
}
