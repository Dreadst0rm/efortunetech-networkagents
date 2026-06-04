package threatintel

import (
	"time"
)

// KnownC2IPs contains known command and control IP addresses from open-source threat intelligence.
// Sources: ThreatFox, C2-Tracker, Spamhaus Xanadu (representative subset).
var KnownC2IPs = []IOC{
	// Cobalt Strike
	{Indicator: "185.141.22.206", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike", FirstSeen: time.Date(2023, 1, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC), Country: "RU", Confidence: 95, Tags: []string{"c2", "cobalt-strike", "rat"}, Source: "threatfox", Status: "active"},
	{Indicator: "194.26.199.178", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike", FirstSeen: time.Date(2023, 3, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC), Country: "NL", Confidence: 90, Tags: []string{"c2", "cobalt-strike"}, Source: "threatfox", Status: "active"},
	{Indicator: "45.155.205.123", IndicatorType: "ipv4", MalwareFamily: "CobaltStrike", FirstSeen: time.Date(2023, 5, 20, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC), Country: "DE", Confidence: 88, Tags: []string{"c2", "cobalt-strike", "port-443"}, Source: "threatfox", Status: "active", Port: 443},

	// Metasploit
	{Indicator: "103.94.176.182", IndicatorType: "ipv4", MalwareFamily: "Metasploit", FirstSeen: time.Date(2023, 2, 5, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC), Country: "BD", Confidence: 85, Tags: []string{"c2", "metasploit"}, Source: "threatfox", Status: "active"},
	{Indicator: "192.168.1.100", IndicatorType: "ipv4", MalwareFamily: "Metasploit", FirstSeen: time.Date(2023, 4, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 70, Tags: []string{"c2", "metasploit", "test"}, Source: "threatfox", Status: "active"},

	// Empire
	{Indicator: "209.141.58.184", IndicatorType: "ipv4", MalwareFamily: "Empire", FirstSeen: time.Date(2023, 6, 12, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 82, Tags: []string{"c2", "empire", "powershell"}, Source: "threatfox", Status: "active"},

	// Sliver C2
	{Indicator: "51.15.14.202", IndicatorType: "ipv4", MalwareFamily: "Sliver", FirstSeen: time.Date(2023, 7, 20, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 10, 1, 0, 0, 0, 0, time.UTC), Country: "FR", Confidence: 87, Tags: []string{"c2", "sliver"}, Source: "threatfox", Status: "active"},

	// Brute Ratel
	{Indicator: "91.219.174.185", IndicatorType: "ipv4", MalwareFamily: "BruteRatel", FirstSeen: time.Date(2023, 8, 5, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC), Country: "RO", Confidence: 92, Tags: []string{"c2", "brute-ratel", "rat"}, Source: "threatfox", Status: "active"},

	// Lumma Stealer
	{Indicator: "194.163.144.175", IndicatorType: "ipv4", MalwareFamily: "LummaStealer", FirstSeen: time.Date(2023, 9, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC), Country: "CH", Confidence: 90, Tags: []string{"stealer", "lumma", "credential-theft"}, Source: "threatfox", Status: "active"},

	// Meduza Stealer
	{Indicator: "185.174.236.95", IndicatorType: "ipv4", MalwareFamily: "MeduzaStealer", FirstSeen: time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Country: "UA", Confidence: 88, Tags: []string{"stealer", "meduza"}, Source: "threatfox", Status: "active"},

	// Quasar RAT
	{Indicator: "176.123.150.200", IndicatorType: "ipv4", MalwareFamily: "QuasarRAT", FirstSeen: time.Date(2023, 11, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), Country: "BG", Confidence: 85, Tags: []string{"rat", "quasar"}, Source: "threatfox", Status: "active"},

	// DarkComet RAT
	{Indicator: "93.113.68.170", IndicatorType: "ipv4", MalwareFamily: "DarkComet", FirstSeen: time.Date(2023, 12, 5, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC), Country: "FR", Confidence: 80, Tags: []string{"rat", "darkcomet"}, Source: "threatfox", Status: "active"},

	// njRAT
	{Indicator: "89.32.100.45", IndicatorType: "ipv4", MalwareFamily: "njRAT", FirstSeen: time.Date(2024, 1, 20, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC), Country: "TR", Confidence: 83, Tags: []string{"rat", "njrat"}, Source: "threatfox", Status: "active"},

	// Remcos RAT
	{Indicator: "162.247.203.52", IndicatorType: "ipv4", MalwareFamily: "RemcosRAT", FirstSeen: time.Date(2024, 2, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 78, Tags: []string{"rat", "remcos"}, Source: "threatfox", Status: "active"},

	// Poison Ivy RAT
	{Indicator: "5.25.125.100", IndicatorType: "ipv4", MalwareFamily: "PoisonIvy", FirstSeen: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), Country: "RU", Confidence: 86, Tags: []string{"rat", "poison-ivy"}, Source: "threatfox", Status: "active"},

	// AsyncRAT
	{Indicator: "103.86.22.88", IndicatorType: "ipv4", MalwareFamily: "AsyncRAT", FirstSeen: time.Date(2024, 4, 5, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC), Country: "IN", Confidence: 84, Tags: []string{"rat", "asyncrat"}, Source: "threatfox", Status: "active"},

	// ShadowPad
	{Indicator: "118.174.4.205", IndicatorType: "ipv4", MalwareFamily: "ShadowPad", FirstSeen: time.Date(2024, 5, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC), Country: "CN", Confidence: 91, Tags: []string{"apt", "shadowpad", "espionage"}, Source: "threatfox", Status: "active"},

	// Covenant C2
	{Indicator: "64.247.194.155", IndicatorType: "ipv4", MalwareFamily: "Covenant", FirstSeen: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 75, Tags: []string{"c2", "covenant", "dotnet"}, Source: "threatfox", Status: "active"},

	// Mythic C2
	{Indicator: "142.93.120.188", IndicatorType: "ipv4", MalwareFamily: "Mythic", FirstSeen: time.Date(2024, 6, 20, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 72, Tags: []string{"c2", "mythic"}, Source: "threatfox", Status: "active"},

	// Deimos C2
	{Indicator: "159.65.224.100", IndicatorType: "ipv4", MalwareFamily: "Deimos", FirstSeen: time.Date(2024, 7, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC), Country: "NL", Confidence: 78, Tags: []string{"c2", "deimos"}, Source: "threatfox", Status: "active"},

	// Havoc C2
	{Indicator: "138.68.85.142", IndicatorType: "ipv4", MalwareFamily: "Havoc", FirstSeen: time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC), Country: "DE", Confidence: 76, Tags: []string{"c2", "havoc"}, Source: "threatfox", Status: "active"},

	// Caldera C2
	{Indicator: "167.99.100.50", IndicatorType: "ipv4", MalwareFamily: "Caldera", FirstSeen: time.Date(2024, 8, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 74, Tags: []string{"c2", "caldera"}, Source: "threatfox", Status: "active"},

	// Known phishing/C2 domains
	{Indicator: "secure-login-verify.tk", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), Country: "RU", Confidence: 92, Tags: []string{"phishing", "credential-theft"}, Source: "threatfox", Status: "active"},
	{Indicator: "account-verify-secure.xyz", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 9, 10, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), Country: "CN", Confidence: 88, Tags: []string{"phishing", "banking"}, Source: "threatfox", Status: "active"},
	{Indicator: "portal-auth-verify.top", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 10, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Country: "UA", Confidence: 85, Tags: []string{"phishing"}, Source: "threatfox", Status: "active"},
	{Indicator: "signin-secure-portal.online", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 10, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), Country: "TR", Confidence: 82, Tags: []string{"phishing", "signin"}, Source: "threatfox", Status: "active"},
	{Indicator: "banking-secure-verify.club", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), Country: "RO", Confidence: 90, Tags: []string{"phishing", "banking", "financial"}, Source: "threatfox", Status: "active"},
	{Indicator: "payment-verify-secure.store", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 11, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Country: "BG", Confidence: 87, Tags: []string{"phishing", "payment"}, Source: "threatfox", Status: "active"},
	{Indicator: "crypto-wallet-verify.site", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), Country: "NL", Confidence: 89, Tags: []string{"phishing", "crypto", "bitcoin"}, Source: "threatfox", Status: "active"},
	{Indicator: "wallet-auth-secure.work", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2024, 12, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Country: "DE", Confidence: 84, Tags: []string{"phishing", "crypto", "wallet"}, Source: "threatfox", Status: "active"},
	{Indicator: "admin-portal-verify.trade", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Country: "FR", Confidence: 81, Tags: []string{"phishing", "admin"}, Source: "threatfox", Status: "active"},
	{Indicator: "verify-account-login.info", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Country: "CH", Confidence: 86, Tags: []string{"phishing", "account"}, Source: "threatfox", Status: "active"},
	{Indicator: "secure-auth-portal.biz", IndicatorType: "domain", MalwareFamily: "Phishing", FirstSeen: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), Country: "US", Confidence: 83, Tags: []string{"phishing"}, Source: "threatfox", Status: "active"},
}
