# NetworkSentinel — Windows Guide

## Overview

NetworkSentinel is a Go-based network security analysis tool that scans local network connections, correlates them to processes, performs multi-heuristic risk scoring, and generates reports.

**Version**: 0.4.0
**License**: Apache 2.0
**Platform**: Windows 10/11, Windows Server 2016+ (x64)

---

## Quick Start

### 1. Run a Scan

```powershell
.\networksentinel.exe
```

This performs a full scan, outputs results to the console, and generates the following files:

```
network_sentinel_<hostname>_<timestamp>.md   — Markdown report
network_sentinel_<hostname>_<timestamp>.json — JSON report
network_sentinel_<hostname>_<timestamp>_connections.csv  — Connection data
network_sentinel_<hostname>_<timestamp>_risks.csv        — Risk analysis
baseline.json                                           — Baseline snapshot
```

### 2. View Reports

Open the generated Markdown report. It contains:

- **System Information** — hostname, OS, local IPs
- **Network Connections Summary** — total connections, outbound/inbound/internal counts, TCP state distribution
- **External Endpoints** — remote address and port listing
- **Suspicious Connections** — flagged connections
- **Risk Analysis Summary** — Critical / High / Medium / Low counts
- **Top Processes by Network Activity** — Top 20 processes
- **Privilege Escalation Analysis** — detected privilege escalation chains
- **Baseline Comparison** — new / gone / unchanged connections

---

## Command-Line Arguments

```
Usage of networksentinel.exe:
  -config string
        Path to config file (default "config.json")
  -daemon int
        Run in daemon mode with scan interval in seconds (0 = one-shot)
  -h    Show help
  -output string
        Output directory for reports (default ".")
```

### Examples

**One-shot scan (default):**
```powershell
.\networksentinel.exe
```

**Specify a config file:**
```powershell
.\networksentinel.exe -config C:\tools\sentinel_config.json
```

**Specify output directory:**
```powershell
.\networksentinel.exe -output C:\reports
```

**Daemon mode (scan every 60 seconds):**
```powershell
.\networksentinel.exe -daemon 60
```

Press `Ctrl+C` to stop the daemon.

---

## Configuration

### Location

Default `config.json`, in the same directory as `networksentinel.exe`.

### Structure

```json
{
  "thresholds": {
    "min_ip_connections": 5,
    "min_process_connections": 5,
    "critical_threshold": 3,
    "high_threshold": 2
  },
  "excluded": {
    "pids": [],
    "processes": []
  },
  "whitelist": [
    {"ip": "8.8.8.8", "comment": "Google DNS"},
    {"ip": "1.1.1.1", "comment": "Cloudflare DNS"}
  ],
  "dns_log": false,
  "alerting": {
    "webhook_url": "",
    "enabled": false
  }
}
```

### Parameter Descriptions

#### thresholds

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `min_ip_connections` | int | 5 | Outbound connections to the same remote IP that triggers an alert |
| `min_process_connections` | int | 5 | Outbound connections from the same process that triggers an alert |
| `critical_threshold` | int | 3 | Number of heuristic reasons needed to mark a connection as Critical |
| `high_threshold` | int | 2 | Number of heuristic reasons needed to mark a connection as High |

#### excluded

Skip scanning for specific PIDs or process names. Commonly used to exclude known-safe system processes.

```json
"excluded": {
  "pids": [4, 444, 1284],
  "processes": ["MsMpEng.exe", "AntimalwareServiceHost.exe"]
}
```

#### whitelist

Mark IP addresses as trusted with an optional comment explaining why. Whitelisted IPs skip suspicious port and process heuristics.

```json
"whitelist": [
  {"ip": "8.8.8.8", "comment": "Google Public DNS"},
  {"ip": "1.1.1.1", "comment": "Cloudflare DNS"},
  {"ip": "185.199.109.133", "comment": "GitHub CDN"}
]
```

#### dns_log (DNS logging)

When enabled, NetworkSentinel queries the DNS client cache via PowerShell WMI and scores domain names for suspiciousness.

```json
"dns_log": true
```

**Windows DNS capture method:** `Get-CimInstance MSFT_DNSClientCache`

**Domain suspiciousness scoring factors:**

| Factor | Score |
|--------|-------|
| Suspicious TLD (.xyz, .tk, .ml, .ga, .cf, .ru, .cn, etc.) | 0.4 - 0.7 |
| High subdomain depth (>= 4 dots) | +0.3 |
| Suspicious keywords (login, account, secure, verify, admin, banking, crypto, etc.) | +0.2 |
| Long domain name (> 50 characters) | +0.4 |
| High consonant ratio (> 5:1) | +0.3 |

Score >= 0.6 is flagged as suspicious.

#### alerting

When enabled, Critical and High risk connections are alerted via Webhook and stderr.

```json
"alerting": {
  "enabled": true,
  "webhook_url": "https://your-webhook.example.com/alerts"
}
```

**Alert output format (stderr):**
```
[2026-06-03 14:30:00] [CRITICAL] stdout: chrome.exe (PID: 3076) -> 173.194.64.188:5228
```

**Alert JSON payload (Webhook POST):**
```json
{
  "timestamp": "2026-06-03T14:30:00.1234567-05:00",
  "level": "critical",
  "message": "chrome.exe (PID: 3076) -> 173.194.64.188:5228",
  "details": "suspicious port 5228; high connection count to 173.194.64.188 (7)"
}
```

---

## Risk Assessment

### 6 Heuristic Rules

All rules are evaluated only for **outbound (outbound)** connections.

#### 1. Suspicious Port Detection

Checks remote ports against known C2/proxy ports:

| Port | Common Use |
|------|------------|
| 4444 | Metasploit default |
| 5555 | Android Debug Bridge |
| 6666-6669 | IRC / C2 |
| 7777 | Common backdoor |
| 8888 / 9999 | Proxy / dev server |
| 1080 / 1081 | SOCKS proxy |
| 3128 | Squid proxy |
| 8080 / 8443 | Proxy / alt HTTPS |
| 1337 | Common C2 |
| 9001 / 9050 / 9051 | Tor |
| 2525 / 4242-4244 | Various C2 |
| 1234 | Common backdoor |

#### 2. Suspicious Process Names

Checks if the process is in the Windows suspicious process list:

```
cmd.exe, powershell.exe, wscript.exe, cscript.exe, wmic.exe,
certutil.exe, bitsadmin.exe, dns.exe, net.exe, ssh.exe,
curl.exe, netsh.exe, sc.exe, whoami.exe, mshta.exe,
regsvr32.exe, msbuild.exe, tasklist.exe, ipconfig.exe
```

#### 3. Abnormal TCP States

Detects TCP states that may indicate scanning or covert channels:

- `SYN_SENT` — Connection establishing
- `SYN_RECEIVED` — Connection completing handshake
- `TIME_WAIT` — Connection closing
- `CLOSE_WAIT` — Remote side closed connection

#### 4. High IP Connection Count

Outbound connections to the same remote IP exceed the `min_ip_connections` threshold.

#### 5. High Process Connection Count

Outbound connections from the same process exceed the `min_process_connections` threshold.

#### 6. Privilege Escalation Chain Detection

Detects dangerous combinations:

| Combination | Description |
|-------------|-------------|
| Elevated + unsigned + temp path | Highest risk |
| Elevated + unsigned | Medium risk |
| Elevated + temp path | Medium risk |

**Detection details:**
- **Privilege level** — Queried via PowerShell token elevation
- **Code signing** — Verified via Authenticode
- **Execution path** — Checks for temp/tmp/AppData\Local\Temp
- **Integrity level** — Low / Medium / High / System

### Risk Levels

| Level | Condition |
|-------|-----------|
| **Critical** | >= `critical_threshold` heuristic reasons (default 3) |
| **High** | >= `high_threshold` heuristic reasons (default 2) |
| **Medium** | Exactly 1 heuristic reason |
| **Low** | 0 reasons (no output) |

---

## Threat Intelligence

NetworkSentinel includes built-in threat intelligence matching against known C2 (command and control) infrastructure. When a connection or DNS query matches a known indicator, the risk assessment is elevated and includes detailed threat intel context.

### Built-in Data Sources

The tool includes **32 indicators** (21 IPv4 addresses, 11 domains) covering:

| Category | Count | Examples |
|----------|-------|----------|
| C2 Frameworks | 10 | CobaltStrike, Metasploit, Empire, Sliver, BruteRatel, Covenant, Mythic, Deimos, Havoc, Caldera |
| Malware Families | 9 | LummaStealer, MeduzaStealer, QuasarRAT, DarkComet, njRAT, RemcosRAT, PoisonIvy, AsyncRAT, ShadowPad |
| Phishing Domains | 11 | secure-login-verify.tk, account-verify-secure.xyz, portal-auth-verify.top, etc. |

Each indicator includes: malware family name, first/last seen date, country code, confidence score (0-100), tags, source data source, and status.

### How It Works

During risk assessment, each outbound connection's remote address is cross-referenced against the C2 database. DNS queries are also cross-referenced. When a match is found:

- **Confidence >= 90** → Risk level elevated to **Critical**
- **Confidence >= 80** → Risk level elevated to **High** (if not already higher)
- Adds `THREAT_INTEL` reason with malware family, source, confidence, country, and tags

Report example:
```
THREAT_INTEL: CobaltStrike (threatfox) confidence=95 country=RU tags=[c2, cobalt-strike, rat]
```

### Updating Data Sources

NetworkSentinel supports two methods for updating threat intelligence:

#### Method 1: External JSON Feed File (Recommended)

Load a JSON feed file at runtime without recompiling:

```powershell
# Download ThreatFox feed
curl -s https://threatfox.abuse.ch/api/v1/export/json/ | python3 -c "
import json, sys, re
data = json.load(sys.stdin)
iocs = []
seen = set()
for ioc in data.get('iocs', [])[:100]:
    ip = ioc.get('ip', '')
    malware = ioc.get('malware', 'Unknown')
    country = ioc.get('country', '??')
    if ip and ip not in seen:
        seen.add(ip)
        iocs.append({'indicator': ip, 'indicator_type': 'ipv4', 'malware_family': malware, 'country': country, 'confidence': 85, 'tags': ['c2'], 'source': 'threatfox', 'status': 'active'})
print(json.dumps(iocs, indent=2))
" > threatintel_feed.json

# Run with the feed
.\networksentinel.exe -feed threatintel_feed.json
```

**Feed format** (`threatintel_feed.json`):
```json
[
  {
    "indicator": "185.141.22.206",
    "indicator_type": "ipv4",
    "malware_family": "CobaltStrike",
    "first_seen": "2024-01-15T00:00:00Z",
    "last_seen": "2024-06-01T00:00:00Z",
    "country": "RU",
    "confidence": 95,
    "tags": ["c2", "cobalt-strike", "rat"],
    "source": "threatfox",
    "status": "active"
  }
]
```

#### Method 2: Code-Based Updates (Requires Rebuild)

For permanent updates, edit `threatintel/feeds.go` and add new `IOC` structs to `KnownC2IPs`, then rebuild:

```powershell
go build -o networksentinel.exe .
```

**Recommended feeds:**

| Source | Format | Coverage |
|--------|--------|----------|
| ThreatFox (abuse.ch) | JSON API | C2 IPs and domains for 50+ frameworks: Cobalt Strike, Metasploit, Empire, Sliver, etc. |
| C2-Tracker (montysecurity) | Plain text | Community-maintained C2 infrastructure from Shodan/Censys |
| Spamhaus Xanadu | Plain text | High-confidence C2 IP blacklist |
| AbuseIPDB | JSON/plain text | Broad IP abuse intelligence with confidence scores |
| PhishStats | JSON | Phishing infrastructure and URLs |

**Automate updates with a script**

Create `update-feeds.ps1` in the project directory:

```powershell
# Download and prepare ThreatFox indicators as JSON feed
$feed = Invoke-RestMethod -Uri "https://threatfox.abuse.ch/api/v1/export/json/"
$iocs = @()
$seen = @{}
foreach ($ioc in $feed.iocs[0..99]) {
    $ip = $ioc.ip
    $malware = $ioc.malware
    $country = $ioc.country
    if ($ip -and -not $seen.ContainsKey($ip)) {
        $seen[$ip] = $true
        $iocs += @{
            indicator = $ip
            indicator_type = "ipv4"
            malware_family = $malware
            country = $country
            confidence = 85
            tags = @("c2")
            source = "threatfox"
            status = "active"
        }
    }
}
$iocs | ConvertTo-Json -Depth 5 > threatintel_feed.json
Write-Host "Feed saved to threatintel_feed.json"
Write-Host "Run: .\networksentinel.exe -feed threatintel_feed.json"
```

**Update frequency recommendation:** Weekly in production, or daily with continuous monitoring.

---

## Baseline Comparison

After each scan, NetworkSentinel automatically saves the current connection snapshot to `baseline.json`. On the next run, it compares current connections against the baseline:

- **New** — connections not seen before
- **Gone** — connections that disappeared
- **Unchanged** — connections present in both scans

On first run there is no baseline; a new one is created.

---

## Daemon Mode

```powershell
.\networksentinel.exe -daemon 60
```

- Runs a full scan every 60 seconds
- Each scan saves a new baseline
- Each scan generates a timestamped report file
- Press `Ctrl+C` to gracefully exit

---

## Output File Details

### Markdown Report

```markdown
# Network Sentinel Report
Hostname: Goliath
OS: windows
Scan Time: 2026-06-03 14:30:00

## Network Connections Summary
Total Connections: 156
Outbound: 89
Inbound: 45
Internal: 22

## Risk Analysis Summary
Critical: 2
High: 5
Medium: 12
Low: 3

## Privilege Escalation Analysis
PID    | Process      | Privilege | Signed | Path
3001   | malware.exe  | elevated  | No     | C:\Users\User1\AppData\Local\Temp\malware.exe
```

### JSON Report

```json
{
  "version": "0.4.0",
  "scan_time": "2026-06-03T14:30:00.1234567-05:00",
  "system": {
    "hostname": "Goliath",
    "os_platform": "windows",
    "local_ips": ["192.168.1.100", "10.0.0.50"]
  },
  "connections": [...],
  "processes": [...],
  "risks": [...],
  "security": {
    "1234": {
      "PID": 1234,
      "Name": "chrome.exe",
      "Username": "User1",
      "ExePath": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
      "PrivLevel": "standard",
      "IsSystem": false,
      "Integrity": "medium",
      "Signer": "Google LLC",
      "IsSigned": true,
      "TokenElev": "default"
    }
  },
  "baseline": {
    "New": [...],
    "Gone": [...],
    "Unchanged": [...],
    "BaselineAge": "5m30s"
  },
  "findings": {
    "TotalOutbound": 89,
    "ExternalEndpoints": 45,
    "SuspiciousPorts": 3,
    "SuspiciousProcesses": 2,
    "PrivEscalationCount": 1,
    "WhitelistedCount": 0
  },
  "dns_lookups": 12
}
```

### CSV Files

**connections.csv** columns:
```
ProcessID,Process,Executable,LocalAddr,LocalPort,DNSName,RemoteAddr,RemotePort,Protocol,State,Direction
```

**risks.csv** columns:
```
RiskLevel,ProcessID,Process,LocalAddr,LocalPort,RemoteAddr,RemotePort,State,Direction,Reasons
```

---

## Privilege Requirements

NetworkSentinel can collect all information with **standard user privileges**. Some features (code signing verification, token elevation detection) require the process to have read permissions, but do not require administrator rights.

**Recommended ways to run:**

```powershell
# Standard user
.\networksentinel.exe

# Administrator (more complete process info)
Start-Process -Verb RunAs -FilePath ".\networksentinel.exe"
```

---

## Troubleshooting

### Scan Fails — "wmic process failed"

Some Windows versions have deprecated `wmic`. Ensure the system supports the wmic command:

```powershell
wmic process get Name,ProcessId /format:list
```

If it fails, the system may have disabled wmic.

### DNS Capture Returns Empty

The `MSFT_DNSClientCache` WMI class may not exist on some Windows versions. DNS capture failure does not affect other functionality.

### Report Not Generated

Check that the output directory exists:

```powershell
.\networksentinel.exe -output C:\reports
# Ensure C:\reports directory exists
```

### Config Load Fails

The config file must be valid JSON:

```powershell
# Validate JSON format
Get-Content config.json | ConvertFrom-Json
```

---

## Performance

- **One-shot scan time**: ~5-15 seconds (depends on process/connection count)
- **Memory usage**: ~20-50 MB
- **Daemon mode**: Each scan runs independently, no memory accumulation

---

## Security Considerations

1. **This tool is for authorized security testing and monitoring only**
2. **Do not run in production without authorization**
3. **The baseline file `baseline.json` contains network connection data — protect it**
4. **Webhook URLs should not be hardcoded in config — use environment variables or a secrets manager**
5. **Daemon mode runs continuously in the background — ensure system security monitoring policies allow it**

---

## Changelog

### v0.4.0
- New CLI flags (-config, -output, -daemon, -h)
- New daemon mode
- New DNS logging and suspicious domain detection
- New Webhook and stderr alerting
- New privilege escalation chain detection
- New code signing verification
- New baseline comparison
- New Markdown / JSON / CSV multi-format reports
- Full platform support (Windows / Linux / macOS)
