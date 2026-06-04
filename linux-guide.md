# NetworkSentinel — Linux Guide

## Overview

NetworkSentinel is a Go-based network security analysis tool that scans local network connections, correlates them to processes, performs multi-heuristic risk scoring, and generates reports.

**Version**: 0.4.0
**License**: Apache 2.0
**Platform**: Linux (x64, ARM64) — supports mainstream distributions

**Supported kernels**: Linux 2.6.32+ (requires `/proc` filesystem)

**Supported distributions**:
- Ubuntu 18.04+
- Debian 10+
- CentOS 7+ / RHEL 7+
- Fedora 30+
- openSUSE 15+
- Arch Linux
- Alpine Linux

---

## Quick Start

### 1. Run a Scan

```bash
./networksentinel_linux
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
Usage of networksentinel_linux:
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
./networksentinel_linux
```

**Custom config file:**
```bash
./networksentinel_linux -config /etc/networksentinel/config.json
```

**Custom output directory:**
```bash
./networksentinel_linux -output /var/log/networksentinel
```

**Daemon mode (scan every 60 seconds):**
```bash
./networksentinel_linux -daemon 60
```

Press `Ctrl+C` to stop the daemon.

**Run daemon in background:**
```bash
nohup ./networksentinel_linux -daemon 300 > /var/log/networksentinel.log 2>&1 &
```

---

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/efortunetech/networksentinel.git
cd networksentinel

# Build Linux version (cross-compile from any platform)
GOOS=linux GOARCH=amd64 go build -o networksentinel_linux .

# ARM64 version
GOOS=linux GOARCH=arm64 go build -o networksentinel_linux_arm64 .
```

### Install to System Path

```bash
sudo cp networksentinel_linux /usr/local/bin/networksentinel
sudo chmod +x /usr/local/bin/networksentinel
```

### Install via systemd (optional)

```bash
# Create systemd service
sudo tee /etc/systemd/system/networksentinel.service > /dev/null << 'EOF'
[Unit]
Description=NetworkSentinel Network Security Scanner
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/networksentinel -daemon 300 -output /var/log/networksentinel
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable networksentinel
sudo systemctl start networksentinel
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
  "processes": ["systemd", "kthreadd", "sshd"]
}
```

#### dns_log

When enabled, NetworkSentinel queries systemd-resolved logs via `journalctl` and performs suspicious domain scoring.

```json
"dns_log": true
```

**Linux DNS capture method:** `journalctl -u systemd-resolved --grep query`

Requires systemd-resolved service to be running.

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
  "timestamp": "2026-06-03T14:30:00.1234567+02:00",
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

Checks if the process matches the Linux suspicious process list:

```
bash, sh, zsh, ksh, fish,
python, python3, perl, ruby,
nc, netcat, curl, wget,
ssh, scp, sftp, rsync,
sudo, su, passwd, crontab,
systemctl, iptables, ip, ifconfig,
netstat, ss, nmap, tcpdump,
awk, sed, grep, find,
base64, xxd, openssl
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
- **Privilege level** — Based on eUID (0=root, 1-999=system account, 1000+=regular user)
- **Execution path** — Checks for /tmp/ or /var/tmp/
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
3. **Rebuild** — `GOOS=linux GOARCH=amd64 go build -o networksentinel_linux .`

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
./networksentinel_linux -daemon 60
```

- Performs a full scan every 60 seconds
- Saves a new baseline after each scan
- Generates timestamped report files after each scan
- Graceful exit on `Ctrl+C`
- Can be paired with systemd for auto-start

---

## Output Files

### Markdown Report

```markdown
# Network Sentinel Report
Hostname: webserver01
OS: linux
Scan Time: 2026-06-03 14:30:00

## Network Connections Summary
Total Connections: 234
Outbound: 156
Inbound: 52
Internal: 26

## Risk Analysis Summary
Critical: 1
High: 3
Medium: 8
Low: 2

## Privilege Escalation Analysis
PID    | Process      | Privilege | Signed | Path
2345   | python3      | elevated  | N/A    | /tmp/.hidden/payload
```

### JSON Report

```json
{
  "version": "0.4.0",
  "scan_time": "2026-06-03T14:30:00.1234567+02:00",
  "system": {
    "hostname": "webserver01",
    "os_platform": "linux",
    "local_ips": ["192.168.1.100", "10.0.0.50"]
  },
  "connections": [...],
  "processes": [...],
  "risks": [...],
  "security": {
    "1234": {
      "PID": 1234,
      "Name": "nginx",
      "Username": "www-data",
      "ExePath": "/usr/sbin/nginx",
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
    "TotalOutbound": 156,
    "ExternalEndpoints": 78,
    "SuspiciousPorts": 2,
    "SuspiciousProcesses": 1,
    "PrivEscalationCount": 1
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

## Linux-Specific Technical Details

### Network Connection Collection

NetworkSentinel reads network connection data directly from the `/proc` filesystem without requiring root:

| Source | Protocol | Description |
|--------|----------|-------------|
| `/proc/net/tcp` | TCP IPv4 | Standard TCP connections |
| `/proc/net/tcp6` | TCP IPv6 | IPv6 TCP connections |
| `/proc/net/udp` | UDP IPv4 | Standard UDP connections |
| `/proc/net/udp6` | UDP IPv6 | IPv6 UDP connections |

### PID Correlation

Connections are matched to processes via inode numbers in `/proc/[pid]/fd/*` symlinks:

```
/proc/1234/fd/0 -> socket:[123456]
/proc/5678/fd/10 -> socket:[123456]
```

When inode `123456` is linked by both PID 1234 and 5678, the first PID is used.

### Process Information

- **Process name** — `/proc/[pid]/comm`
- **Executable path** — `/proc/[pid]/exe` symlink
- **Username** — UID read from `/proc/[pid]/status`, mapped against `/etc/passwd`
- **Privilege level** — Based on effective UID:
  - `euid == 0` → root/SYSTEM
  - `1 <= euid <= 999` → system account/Elevated
  - `euid >= 1000` → regular user/Standard

### Unsupported Features (Linux)

- **Code signing verification** — Linux binaries do not use Authenticode signing
- **Integrity level** — Inferred from UID range, not kernel integrity tokens
- **Token elevation** — Linux has no UAC concept, based solely on UID

---

## Privilege Requirements

### Minimum Privileges

NetworkSentinel can run as a **regular user**, reading `/proc` and `/proc/net/*` files.

### Recommended Privileges

```bash
# Run as regular user (basic functionality)
./networksentinel_linux

# Run as root (full process information)
sudo ./networksentinel_linux
```

**Advantages of running as root:**
- Can read `/proc/[pid]/exe` symlinks for all processes
- Can read `/proc/[pid]/status` for all processes
- Some protected process information may require root access

### Configure Minimal Privileges via sudoers

```bash
# Create dedicated sudoers config
sudo tee /etc/sudoers.d/networksentinel > /dev/null << 'EOF'
netmon ALL=(ALL) NOPASSWD: /usr/local/bin/networksentinel_linux
EOF
sudo chmod 440 /etc/sudoers.d/networksentinel
```

---

## Troubleshooting

### Scan Fails — "read /proc: permission denied"

The current user lacks permission to read `/proc`. Use sudo:

```bash
sudo ./networksentinel_linux
```

### DNS Capture Returns Empty

`journalctl -u systemd-resolved` may fail if:
- systemd-resolved is not running
- user lacks journal read permission
- no DNS query records in the log

DNS capture failure does not affect other functionality.

### IPv6 Connections Not Showing

Ensure IPv6 is enabled and `/proc/net/tcp6` and `/proc/net/udp6` exist:

```bash
ls /proc/net/tcp6 /proc/net/udp6
```

### Reports Not Generated

Verify the output directory exists:

```bash
./networksentinel_linux -output /var/log/networksentinel
# Ensure directory exists
mkdir -p /var/log/networksentinel
```

### Config Loading Fails

The config file must be valid JSON:

```bash
# Validate JSON format
python3 -m json.tool config.json
```

### Process Correlation Fails (PID = -1)

Some connections cannot be correlated to a process (no inode, kernel optimizations, etc.). This is normal and does not indicate a scan failure.

---

## Performance

- **Single scan time**: ~3-10 seconds (depends on process/connection count)
- **Memory usage**: ~10-30 MB
- **Daemon mode**: Each scan runs independently, no memory accumulation
- **I/O impact**: Reads `/proc` filesystem, virtually no disk I/O

---

## Security Considerations

1. **This tool is for authorized security testing and monitoring only**
2. **Do not run in production without authorization**
3. **The baseline file `baseline.json` contains network connection data — protect it**
4. **Webhook URLs should not be hardcoded in config — use environment variables or a secrets manager**
5. **Daemon mode runs continuously in the background — ensure system security monitoring policies allow it**
6. **When running as root, ensure proper log auditing is configured**
7. **Rotate baseline files regularly to avoid stale baselines**

---

## systemd Integration

### Create a Service Unit

```bash
sudo tee /etc/systemd/system/networksentinel.service > /dev/null << 'EOF'
[Unit]
Description=NetworkSentinel Network Security Scanner
After=network.target systemd-resolved.service

[Service]
Type=simple
ExecStart=/usr/local/bin/networksentinel_linux -daemon 300 -output /var/log/networksentinel
Restart=always
RestartSec=10
User=netmon
Group=netmon
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
```

### Create a Dedicated User

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netmon
sudo mkdir -p /var/log/networksentinel
sudo chown netmon:netmon /var/log/networksentinel
sudo chmod 750 /var/log/networksentinel
```

### Start the Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now networksentinel
sudo systemctl status networksentinel
```

---

## Log Integration

### View Daemon Logs via journald

```bash
journalctl -u networksentinel -f
```

### Forward Alerts via syslog

Add to `/etc/systemd/system/networksentinel.service`:

```ini
[Service]
StandardError=syslog
SyslogIdentifier=networksentinel
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

### Linux-Specific
- Connection collection via `/proc/net/tcp{,6}` and `/proc/net/udp{,6}`
- Connection-to-process correlation via `/proc/[pid]/fd/*` inodes
- UID/username retrieval via `/proc/[pid]/status`
- IPv4 and IPv6 support
- Pure Go, no CGo
- Supports all mainstream Linux distributions
