# NetworkSentinel — macOS Guide

## Overview

NetworkSentinel is a Go-based network security analysis tool that scans local network connections, correlates them to processes, performs multi-heuristic risk scoring, and generates reports.

**Version**: 0.4.0
**License**: Apache 2.0
**Platform**: macOS (x64, Apple Silicon/ARM64)

**Supported versions**: macOS 10.14 (Mojave) and later

**Supported hardware**: Intel Macs, Apple Silicon (M1/M2/M3) Macs

---

## Quick Start

### 1. Run a Scan

```bash
./networksentinel_darwin
```

This performs a full scan, outputs results to the terminal, and generates the following files:

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
Usage of networksentinel_darwin:
  -config string
        Config file path (default "config.json")
  -daemon int
        Daemon mode scan interval in seconds, 0 = one-shot mode
  -h    Show help
  -output string
        Report output directory (default ".")
```

### Examples

**One-shot scan (default):**
```bash
./networksentinel_darwin
```

**Custom config file:**
```bash
./networksentinel_darwin -config /etc/networksentinel/config.json
```

**Custom output directory:**
```bash
./networksentinel_darwin -output /var/log/networksentinel
```

**Daemon mode (scan every 60 seconds):**
```bash
./networksentinel_darwin -daemon 60
```

Press `Ctrl+C` to stop the daemon.

**Run daemon in background:**
```bash
nohup ./networksentinel_darwin -daemon 300 > /var/log/networksentinel.log 2>&1 &
```

---

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/efortunetech/networksentinel.git
cd networksentinel

# Build macOS version (cross-compile from any platform)
GOOS=darwin GOARCH=amd64 go build -o networksentinel_darwin .

# Apple Silicon version
GOOS=darwin GOARCH=arm64 go build -o networksentinel_darwin_arm64 .
```

### Install to System Path

```bash
sudo cp networksentinel_darwin /usr/local/bin/networksentinel
sudo chmod +x /usr/local/bin/networksentinel
```

### Download Pre-built Binary

```bash
# Download for Apple Silicon
curl -L -o /usr/local/bin/networksentinel https://github.com/efortunetech/networksentinel/releases/latest/download/networksentinel_darwin_arm64
sudo chmod +x /usr/local/bin/networksentinel

# Download for Intel Macs
curl -L -o /usr/local/bin/networksentinel https://github.com/efortunetech/networksentinel/releases/latest/download/networksentinel_darwin
sudo chmod +x /usr/local/bin/networksentinel
```

---

## Configuration

### Location

Default `config.json`, in the same directory as `networksentinel`.

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
  "dns_log": false,
  "alerting": {
    "webhook_url": "",
    "enabled": false
  }
}
```

### Parameters

#### thresholds

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `min_ip_connections` | int | 5 | Outbound connections to same remote IP to trigger alert |
| `min_process_connections` | int | 5 | Outbound connections from same process to trigger alert |
| `critical_threshold` | int | 3 | Number of heuristic reasons needed for Critical level |
| `high_threshold` | int | 2 | Number of heuristic reasons needed for High level |

#### excluded

Skip specific PIDs or process names during scanning. Useful for excluding known safe system processes.

```json
"excluded": {
  "pids": [1, 2, 100],
  "processes": ["kernel_task", "launchd"]
}
```

#### dns_log

When enabled, NetworkSentinel queries macOS system logs via `log` command and performs suspicious domain scoring.

```json
"dns_log": true
```

**macOS DNS capture methods:**
- `dscacheutil -q host -a name` — DNS cache query
- `log show --predicate "eventMessage CONTAINS 'DNS'"` — System log DNS entries

Requires the `log` command (built into macOS).

**Domain suspicion scoring factors:**

| Factor | Score |
|--------|-------|
| Suspicious TLD (.xyz, .tk, .ml, .ga, .cf, .ru, .cn, etc.) | 0.4 - 0.7 |
| High subdomain depth (>= 4 dots) | +0.3 |
| Suspicious keywords (login, account, secure, verify, admin, banking, crypto, etc.) | +0.2 |
| Unusually long domain (> 50 chars) | +0.4 |
| High consonant-to-vowel ratio (> 5:1) | +0.3 |

Score >= 0.6 is flagged as suspicious.

#### alerting

When enabled, Critical and High risk connections are sent via Webhook and stderr.

```json
"alerting": {
  "enabled": true,
  "webhook_url": "https://your-webhook.example.com/alerts"
}
```

**Alert output format (stderr):**
```
[2026-06-03 14:30:00] [CRITICAL] stdout: python3 (PID: 2345) -> 198.51.100.50:4444
```

**Alert JSON payload (Webhook POST):**
```json
{
  "timestamp": "2026-06-03T14:30:00.1234567-07:00",
  "level": "critical",
  "message": "python3 (PID: 2345) -> 198.51.100.50:4444",
  "details": "suspicious port 4444; high connection count to 198.51.100.50 (7)"
}
```

---

## Risk Assessment

### 6 Heuristic Rules

All rules are evaluated only for **outbound** connections.

#### 1. Suspicious Port Detection

Checks if the remote port matches known C2/proxy ports:

| Port | Common Use |
|------|------------|
| 4444 | Metasploit default |
| 5555 | Android Debug Bridge |
| 6666-6669 | IRC / C2 |
| 7777 | Common backdoor |
| 8888 / 9999 | Proxy / dev server |
| 1080 / 1081 | SOCKS proxy |
| 3128 | Squid proxy |
| 8080 / 8443 | Proxy / alt-HTTPS |
| 1337 | Common C2 |
| 9001 / 9050 / 9051 | Tor |
| 2525 / 4242-4244 | Various C2 |
| 1234 | Common backdoor |

#### 2. Suspicious Process Name

Checks if the process matches the macOS suspicious process list:

```
/bin/sh, /bin/bash, /bin/zsh, /bin/fish,
/usr/bin/python, /usr/local/bin/python3,
nc, netcat, curl, wget,
ssh, scp, sftp, rsync,
sudo, su, openssl, base64
```

#### 3. Anomalous TCP State

Flags TCP states that may indicate scanning or covert channels:

- `SYN_SENT` — Connection establishing
- `SYN_RECEIVED` — Connection completing handshake
- `TIME_WAIT` — Connection closing
- `CLOSE_WAIT` — Remote side closed connection

#### 4. High IP Connection Count

Outbound connections to the same remote IP exceed `min_ip_connections` threshold.

#### 5. High Process Connection Count

Outbound connections from the same process exceed `min_process_connections` threshold.

#### 6. Privilege Escalation Chain Detection

Flags dangerous combinations:

| Combination | Description |
|-------------|-------------|
| Elevated + unsigned + temp path | Highest risk |
| Elevated + unsigned | Medium risk |
| Elevated + temp path | Medium risk |

**Detection details:**
- **Privilege level** — Based on UID (0=root, 1-999=system account, 1000+=regular user)
- **Execution path** — Checks for /tmp/, /private/tmp/, /var/folders/
- **Integrity level** — Inferred from UID range

### Risk Levels

| Level | Condition |
|-------|-----------|
| **Critical** | >= `critical_threshold` heuristic reasons (default 3) |
| **High** | >= `high_threshold` heuristic reasons (default 2) |
| **Medium** | Exactly 1 heuristic reason |
| **Low** | 0 reasons (not output) |

---

## Threat Intelligence Feeds

NetworkSentinel includes built-in threat intelligence matching against known C2 (Command & Control) infrastructure. When a connection or DNS query matches a known indicator, the risk assessment is elevated with detailed threat intel context.

### Built-in Feed

The tool ships with **33 indicators** (22 IP addresses, 11 domains) covering:

| Category | Count | Examples |
|----------|-------|----------|
| C2 Frameworks | 10 | CobaltStrike, Metasploit, Empire, Sliver, BruteRatel, Covenant, Mythic, Deimos, Havoc, Caldera |
| Malware Families | 9 | LummaStealer, MeduzaStealer, QuasarRAT, DarkComet, njRAT, RemcosRAT, PoisonIvy, AsyncRAT, ShadowPad |
| Phishing Domains | 11 | secure-login-verify.tk, account-verify-secure.xyz, portal-auth-verify.top, etc. |

Each indicator includes: malware family name, first/last seen dates, country code, confidence score (0-100), tags, source feed, and status.

### How It Works

During risk assessment, each outbound connection's remote address is checked against the C2 database. DNS queries are also cross-referenced. When a match is found:

- **Confidence >= 90** → Risk level elevated to **Critical**
- **Confidence >= 80** → Risk level elevated to **High** (if not already higher)
- A `THREAT_INTEL` reason is added with malware family, source, confidence, country, and tags

Example from the report:
```
THREAT_INTEL: CobaltStrike (threatfox) confidence=95 country=RU tags=[c2, cobalt-strike, rat]
```

### Updating Feeds

The built-in feed is a representative subset from open-source threat intelligence (ThreatFox, C2-Tracker, Spamhaus Xanadu). To update with fresh indicators:

1. **Download a new feed** — Choose a source (see below)
2. **Add indicators to the code** — Edit `threatintel/feeds.go` and append new `IOC` structs to `KnownC2IPs`
3. **Rebuild** — `GOOS=darwin GOARCH=arm64 go build -o networksentinel_darwin .`

**Recommended feed sources:**

| Source | Format | What It Covers |
|--------|--------|----------------|
| ThreatFox (abuse.ch) | JSON API | C2 IPs and domains from Cobalt Strike, Metasploit, Empire, Sliver, and 50+ frameworks |
| C2-Tracker (montysecurity) | Plain text | Community-curated C2 infrastructure from Shodan/Censys |
| Spamhaus Xanadu | Plain text | High-fidelity C2 IP blocklist |
| AbuseIPDB | JSON/Plaintext | Broad IP abuse intelligence with confidence scores |
| PhishStats | JSON | Phishing infrastructure and URLs |

**Example: Adding from ThreatFox**

```bash
# Download ThreatFox feed
curl -s https://threatfox.abuse.ch/export/tcp/json/ | python3 -c "
import json, sys
data = json.load(sys.stdin)
for ioc in data['iocs'][:50]:  # top 50
    print(f'{ioc[\"ip\"]} {ioc[\"malware\"]} {ioc[\"country\"]} {ioc[\"port\"]}')
"
```

Then add the indicators to `threatintel/feeds.go`:

```go
var KnownC2IPs = []IOC{
    // ... existing indicators ...
    {Indicator: "185.141.22.206", IndicatorType: "ipv4", MalwareFamily: "NewC2Framework", FirstSeen: time.Now(), LastSeen: time.Now(), Country: "US", Confidence: 90, Tags: []string{"c2", "new-framework"}, Source: "threatfox", Status: "active", Port: 443},
}
```

**Automating updates with a script**

Create `update-feeds.sh` in your project directory:

```bash
#!/bin/bash
# Download and prepare ThreatFox indicators for manual addition
curl -s https://threatfox.abuse.ch/api/v1/browse/ | \
    python3 -c "
import json, sys, re
data = json.load(sys.stdin)
# Extract unique IPs with malware family
seen = set()
for ioc in data.get('iocs', [])[:100]:
    ip = ioc.get('ip', '')
    malware = ioc.get('malware', 'Unknown')
    country = ioc.get('country', '??')
    if ip and ip not in seen:
        seen.add(ip)
        print(f'# ThreatFox: {ip} ({malware}, {country})')
" > threatfox_indicators.txt

echo "Review threatfox_indicators.txt and manually add new IOC structs to threatintel/feeds.go"
```

**Update frequency recommendation:** Update threat intel feeds weekly for production environments, or daily if running continuous monitoring.

---

## Baseline Comparison

After each scan, NetworkSentinel saves the current connection snapshot to `baseline.json`. On the next run, it compares current connections against the baseline:

- **New** — connections not seen before
- **Gone** — connections that disappeared
- **Unchanged** — connections present in both scans

The first run creates a baseline if none exists.

---

## Daemon Mode

```bash
./networksentinel_darwin -daemon 60
```

- Performs a full scan every 60 seconds
- Saves a new baseline after each scan
- Generates timestamped report files after each scan
- Graceful exit on `Ctrl+C`

---

## Output Files

### Markdown Report

```markdown
# Network Sentinel Report
Hostname: macbook-pro
OS: darwin
Scan Time: 2026-06-03 14:30:00

## Network Connections Summary
Total Connections: 89
Outbound: 56
Inbound: 18
Internal: 15

## Risk Analysis Summary
Critical: 0
High: 2
Medium: 5
Low: 1

## Privilege Escalation Analysis
PID    | Process      | Privilege | Signed | Path
2345   | python3      | elevated  | N/A    | /tmp/.hidden/payload
```

### JSON Report

```json
{
  "version": "0.4.0",
  "scan_time": "2026-06-03T14:30:00.1234567-07:00",
  "system": {
    "hostname": "macbook-pro",
    "os_platform": "darwin",
    "local_ips": ["192.168.1.100", "10.0.0.50"]
  },
  "connections": [...],
  "processes": [...],
  "risks": [...],
  "security": {
    "1234": {
      "PID": 1234,
      "Name": "Safari",
      "Username": "jdoe",
      "ExePath": "/Applications/Safari.app/Contents/MacOS/Safari",
      "PrivLevel": "standard",
      "IsSystem": false,
      "Integrity": "medium",
      "Signer": "N/A",
      "IsSigned": false,
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
    "TotalOutbound": 56,
    "ExternalEndpoints": 28,
    "SuspiciousPorts": 1,
    "SuspiciousProcesses": 0,
    "PrivEscalationCount": 0
  }
}
```

### CSV Files

**connections.csv** columns:
```
ProcessID,Process,Executable,LocalAddr,LocalPort,RemoteAddr,RemotePort,Protocol,State,Direction
```

**risks.csv** columns:
```
RiskLevel,ProcessID,Process,LocalAddr,LocalPort,RemoteAddr,RemotePort,State,Direction,Reasons
```

---

## macOS-Specific Technical Details

### Network Connection Collection

NetworkSentinel uses `lsof -nP -i` to enumerate network connections on macOS:

- `-n` — Skips port name resolution (faster)
- `-p` — Shows numeric addresses
- `-i` — Lists network files

The output is parsed to extract process ID, local/remote addresses, ports, protocol (TCP/UDP), and TCP state.

### PID Correlation

Process-to-connection correlation is handled directly by `lsof`, which includes the PID in each line of output. No inode-based mapping is needed.

### Process Information

- **Process name** — `ps -p <pid> -o comm=,uid=`
- **Executable path** — `which <command>`
- **Username** — UID from `ps`, mapped against `/etc/passwd`
- **Privilege level** — Based on UID:
  - `uid == 0` → root/SYSTEM
  - `1 <= uid <= 999` → system account/Elevated
  - `uid >= 1000` → regular user/Standard

### lsof Output Parsing

`lsof` output lines are parsed right-to-left to find the NAME column (last field(s)), which contains:
- Parenthesized state: `(ESTABLISHED)`, `(LISTEN)`, etc.
- Bracketed state: `[LISTEN]`
- Address:port pairs: `192.168.1.100:443 -> 10.0.0.50:5228`

The `->` arrow notation indicates TCP connections with a remote endpoint. Single endpoints (no `->`) indicate UDP or listening TCP.

### Unsupported Features (macOS)

- **Code signing verification** — macOS binaries use codesign, not Authenticode
- **Integrity level** — Inferred from UID range, not kernel integrity tokens
- **Token elevation** — macOS has no UAC concept, based solely on UID

---

## Privilege Requirements

### Minimum Privileges

NetworkSentinel can run as a **regular user** for basic scanning. However, `lsof` may require elevated privileges to see all connections.

### Recommended Privileges

```bash
# Run as regular user (limited process visibility)
./networksentinel_darwin

# Run as root (full process visibility)
sudo ./networksentinel_darwin
```

**Advantages of running as root:**
- Can read `lsof` output for all processes
- Can read process info for protected processes
- Some system-level connections may be hidden from regular users

### Gatekeeper and Notarization

macOS Gatekeeper may block unsigned binaries. To run:

```bash
# Run once to bypass Gatekeeper
xattr -d com.apple.quarantine networksentinel_darwin

# Or run with quarantine flag removed
sudo xattr -d com.apple.quarantine networksentinel_darwin
```

---

## Troubleshooting

### Scan Fails — "lsof -nP -i failed"

`lsof` may fail if not installed or if the user lacks permissions:

```bash
# Check lsof is available
which lsof

# Run with sudo if needed
sudo ./networksentinel_darwin
```

### DNS Capture Returns Empty

The `log` command may fail if:
- No DNS-related entries in the system log
- User lacks permission to read system logs
- macOS logging configuration limits access

DNS capture failure does not affect other functionality.

### Reports Not Generated

Verify the output directory exists:

```bash
./networksentinel_darwin -output /var/log/networksentinel
# Ensure directory exists
mkdir -p /var/log/networksentinel
```

### Config Loading Fails

The config file must be valid JSON:

```bash
# Validate JSON format
python3 -m json.tool config.json
```

### Process Correlation Fails

Some processes may not appear in `lsof` output if they are hidden or protected. This is normal and does not indicate a scan failure.

---

## Performance

- **Single scan time**: ~2-8 seconds (depends on process/connection count)
- **Memory usage**: ~10-25 MB
- **Daemon mode**: Each scan runs independently, no memory accumulation
- **I/O impact**: Minimal — reads from `lsof` and `/etc/passwd`

---

## Security Considerations

1. **This tool is for authorized security testing and monitoring only**
2. **Do not run in production without authorization**
3. **The baseline file `baseline.json` contains network connection data — protect it**
4. **Webhook URLs should not be hardcoded in config — use environment variables or a secrets manager**
5. **Daemon mode runs continuously in the background — ensure system security monitoring policies allow it**
6. **When running as root, ensure proper logging is configured**
7. **Regularly rotate baseline files to avoid stale baselines**
8. **On macOS with SIP (System Integrity Protection), some system-level information may be restricted even with root**

---

## Launchd Integration

### Create a Service Unit

```bash
sudo tee /Library/LaunchDaemons/com.efortnet.networksentinel.plist > /dev/null << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD//PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.efortnet.networksentinel</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/networksentinel</string>
        <string>-daemon</string>
        <string>300</string>
        <string>-output</string>
        <string>/var/log/networksentinel</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/networksentinel/daemon.err</string>
    <key>StandardOutPath</key>
    <string>/var/log/networksentinel/daemon.out</string>
    <key>UserName</key>
    <string>netmon</string>
</dict>
</plist>
EOF
```

### Create a Dedicated User

```bash
sudo dscl . -create /Users/netmon
sudo dscl . -create /Users/netmon UserShell /usr/bin/false
sudo dscl . -create /Users/netmon UniqueID -1
sudo dscl . -create /Users/netmon PrimaryGroupID 999
sudo dscl . -create /Users/netmon NFSHomeDirectory /var/log/networksentinel
sudo mkdir -p /var/log/networksentinel
sudo chown netmon:wheel /var/log/networksentinel
sudo chmod 750 /var/log/networksentinel
```

### Load the Service

```bash
sudo launchctl load /Library/LaunchDaemons/com.efortnet.networksentinel.plist
sudo launchctl start com.efortnet.networksentinel
sudo launchctl list com.efortnet.networksentinel
```

### View Logs

```bash
# View daemon logs
tail -f /var/log/networksentinel/daemon.err
tail -f /var/log/networksentinel/daemon.out

# View system logs
log show --predicate 'process == networksentinel' --last 1h
```

---

## Changelog

### v0.4.0
- Added CLI arguments (-config, -output, -daemon, -h)
- Added daemon mode
- Added DNS logging and suspicious domain detection
- Added Webhook and stderr alerting
- Added privilege escalation chain detection
- Added baseline comparison
- Added Markdown / JSON / CSV multi-format reports
- Cross-platform support (Windows / Linux / macOS)

### macOS-Specific
- Connection collection via `lsof -nP -i`
- Process enumeration via `ps axco pid,comm`
- Process info via `ps -p <pid> -o comm=,uid=` and `which`
- UID-based privilege detection from `/etc/passwd`
- DNS capture via `dscacheutil` and `log`
- Pure Go, no CGo
- Supports Intel and Apple Silicon Macs
