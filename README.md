# NetworkSentinel

A cross-platform network security analysis tool written in Go. NetworkSentinel performs real-time network connection analysis, process-level correlation, and multi-heuristic risk scoring.

## Features

- **Cross-platform scanning** — Windows, Linux, macOS via build tags (no CGo)
- **Multi-heuristic risk scoring** — 6 independent risk indicators (ports, process names, TCP states, connection counts, privilege escalation, code signing)
- **Process correlation** — Maps network connections to owning processes with security context
- **Privilege escalation detection** — Identifies elevated + unsigned + temp path chains
- **Code signing verification** — Authenticode signature checks on Windows
- **Baseline comparison** — Tracks new, gone, and unchanged connections across runs
- **Multi-format reports** — Markdown, JSON, and CSV output
- **DNS analysis** — Suspicious domain detection with DGA/C2 indicators
- **Threat intelligence** — Built-in C2 IP/domain matching (33 indicators from ThreatFox, C2-Tracker, Spamhaus)
- **Alerting** — Webhook and stdout alert delivery for critical findings
- **Daemon mode** — Continuous monitoring with configurable scan intervals

## Installation

```bash
go build -o networksentinel .
```

Cross-compile for other platforms:

```bash
GOOS=linux GOARCH=amd64 go build -o networksentinel_linux .
GOOS=darwin GOARCH=arm64 go build -o networksentinel_darwin .
```

## Usage

### One-shot scan

```bash
./networksentinel
```

### Daemon mode (continuous monitoring)

```bash
./networksentinel -daemon 60
```

Scans every 60 seconds until interrupted (Ctrl+C).

### CLI flags

| Flag | Description | Default |
|------|-------------|---------|
| `-config` | Path to config file | `config.json` |
| `-output` | Output directory for reports | `.` |
| `-daemon` | Scan interval in seconds (0 = one-shot) | `0` |
| `-h` | Show help | |

## Configuration

Create a `config.json` file:

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

### Thresholds

| Setting | Description |
|---------|-------------|
| `min_ip_connections` | Connections to same IP before flagging |
| `min_process_connections` | Outbound connections per process before flagging |
| `critical_threshold` | Number of heuristics to trigger critical risk |
| `high_threshold` | Number of heuristics to trigger high risk |

### Exclusions

Skip specific PIDs or process names from scanning. Useful for excluding known safe processes (e.g., antivirus, system services).

## Output

Each scan produces:

- `network_sentinel_<hostname>_<timestamp>.md` — Full Markdown report
- `network_sentinel_<hostname>_<timestamp>.json` — Structured JSON report
- `network_sentinel_<hostname>_<timestamp>_connections.csv` — Connection data
- `network_sentinel_<hostname>_<timestamp>_risks.csv` — Risk analysis
- `baseline.json` — Saved snapshot for future comparison

## Architecture

```
main.go
├── scanner/        — Connection enumeration + risk heuristics
├── processinfo/    — Per-PID security context (privilege, signing, integrity)
├── report/         — Markdown, JSON, CSV report generation
├── baseline/       — Snapshot diffing (new/gone/unchanged)
├── config/         — Configuration loading and threshold management
├── systeminfo/     — Hostname, OS, network interfaces
├── dns/            — DNS query logging and suspicious domain detection
├── threatintel/    — C2 threat intelligence database and feed matching
├── alerting/       — Webhook and stdout alert delivery
└── version/        — Version string management
```

## Risk Heuristics

1. **Suspicious port** — Connections to known C2/proxy ports (4444, 8080, 1337, etc.)
2. **Suspicious process** — Process names commonly used by attackers (cmd.exe, powershell.exe, certutil.exe, etc.)
3. **Anomalous TCP state** — SYN_SENT, SYN_RECEIVED, TIME_WAIT, CLOSE_WAIT
4. **High IP connection count** — Many connections to the same remote IP
5. **High process connection count** — Many outbound connections from one process
6. **Privilege escalation chain** — Elevated + unsigned binary + temp path
7. **Threat intelligence matching** — Cross-references connections against known C2 infrastructure (33 built-in indicators)

## Threat Intelligence Feeds

NetworkSentinel includes 33 built-in indicators covering 10 C2 frameworks, 9 malware families, and 11 phishing domains. To update:

1. Download a feed from [ThreatFox](https://threatfox.abuse.ch), [C2-Tracker](https://github.com/montysecurity/C2-Tracker), or [Spamhaus](https://www.spamhaus.org)
2. Add new indicators to `threatintel/feeds.go` as `IOC` structs in the `KnownC2IPs` slice
3. Rebuild: `go build -o networksentinel .`

See platform-specific guides for detailed update instructions.

## Testing

```bash
go test ./...
```

## CI

GitHub Actions runs on push/PR:
- Tests on Windows, Linux, macOS
- Cross-compilation for all three platforms
- golangci-lint

```bash
# Run locally
go test -v -cover ./...
```

## License

Apache 2.0
