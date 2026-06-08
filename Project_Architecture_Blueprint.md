# NetworkSentinel — Project Architecture Blueprint

> **Generated:** 2026-06-05
> **Module:** `networksentinel` (Go 1.26)
> **Architecture:** Modular monolith with cross-platform plugin pattern
> **Primary pattern:** Pipeline orchestration with platform-specific abstraction
> **Technology:** Go + Wails (UI) + Miekg/DNS library

---

## 1. Architecture Detection and Analysis

### 1.1 Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Language | Go 1.26 (compiled, statically linked) | Core logic |
| CLI | `flag` standard library | Command-line interface |
| UI Framework | Wails v2 (Go + HTML/CSS/JS bridge) | Desktop GUI |
| DNS Library | `github.com/miekg/dns` | DNS protocol queries |
| Platform APIs | `exec.Command` + PowerShell (Windows), `/proc` (Linux), `lsof`/`ps` (macOS) | OS-level data collection |
| External APIs | ThreatFox, C2IntelFeeds (GitHub CSV), custom JSON feeds | Threat intelligence |

### 1.2 Architectural Pattern

The project implements a **pipeline orchestration architecture** with **cross-platform plugin abstraction**:

- **Pipeline:** `main.go` orchestrates a 5-step deterministic scan pipeline
- **Platform abstraction:** Build tags (`//go:build windows`, `linux`, `darwin`) swap implementations without changing shared logic
- **Dependency injection:** `config.Config` flows through all pipeline stages — no global state
- **Data bundling:** `report.Data` aggregates all scan results into a single struct for report generators

---

## 2. Architectural Overview

### 2.1 Core Design Principles

1. **No global state** — Every configurable value flows through `*config.Config`; scanner, threat intel, and report modules receive it as parameters
2. **Platform isolation** — Shared logic in `*.go` files; platform-specific code in `*_windows.go`, `*_linux.go`, `*_darwin.go`
3. **Zero-allocation hot paths** — `AssessConnectionRisk` uses on-stack `[6]string` for heuristic reasons; `itoa()` avoids `fmt.Sprintf` allocation
4. **Defensive configuration** — Invalid whitelist IPs are cleared at load time (not crashed); thresholds validated with minimums enforced

### 2.2 Architectural Boundaries

| Boundary | Enforcement |
|----------|-------------|
| Layer separation | `scanner` imports `config` + `processinfo` + `threatintel`; never imported by `config` |
| Platform isolation | `//go:build` tags ensure only one OS implementation compiles per target |
| Module independence | `c2update/` is a separate Go module (`go mod replace` directive), built independently |
| UI isolation | `ui/` is a separate package; Wails `Bind` exposes only `App` methods to JavaScript |

---

## 3. Architecture Visualization

### 3.1 End-to-End Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                  main.go                                       │
│                              (Orchestrator)                                    │
│                                                                                 │
│  CLI Parse ──► config.Load ──► [ daemon? runDaemon() : runScan() ]            │
└────┬────────────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           runScan() — 5-Step Pipeline                           │
├──────────┬──────────────────────────────────────────────────────────────────────┤
│          │                                                                      
│  [1/5]   │ System Info                                                          │
│          │ ┌─────────────────────────────────────────────────────────┐         
│          │ │ systeminfo.Gather()                                       │         
│          │ │   → os.Hostname() + runtime.GOOS + net.Interfaces()     │         
│          │ └──────────┬──────────────────────────────────────────────┘         
│          │            │ SystemDetails{hostname, OS, localIPs, MACs}           
│          ▼            ▼                                                           │
│  [2/5]   │ Scanner                                                                  │
│          │ ┌─────────────────────────────────────────────────────────┐         
│          │ │ scanner.ScanAll(cfg)                                    │         
│          │ │   ├─ enumerateProcesses()    [platform-specific]        │         
│          │ │   ├─ getNetConnections()     [platform-specific]        │         
│          │ │   ├─ correlate PID → process name                       │         
│          │ │   ├─ determineDirection()    [outbound/internal/in]     │         
│          │ │   ├─ filter excluded (cfg)                              │         
│          │ │   └─ processinfo.GetProcessInfo(pid) × unique PIDs     │         
│          │ └───────┬────────────────────────────────────────────────┘         
│          │         │ []Connection, []ProcessEntry, map[int]SecurityInfo       
│          ▼         ▼                                                             │
│  DNS     │ ResolveConnectionsDNS(conns, concurrency)                            │
│          │   → Parallel worker pool (cfg.DNS.LookupConcurrency, default 10)     │
│          │   → 2s timeout per lookup, deduplicates addresses                    │
│          │   → Populates c.DNSName for resolved connections                     │
│          ▼                                                                     │
│  [DNS]   │ CaptureDNSQueries(cfg, hostname) [if cfg.DNSLog]                    │
│          │   → Platform-specific DNS cache capture                              │
│          │   → Cross-reference: ipToDomain → populate remaining DNSNames        │
│          │   → Save to JSON file                                                │
│          ▼                                                                     │
│  [3/5]   │ Baseline                                                             │
│          │ ┌─────────────────────────────────────────────────────────┐         
│          │ │ baseline.Load(baseline.json)                            │         
│          │ │ baseline.Diff(current, previous)                        │         
│          │ │ baseline.Save(current)                                  │         
│          │ └─────────────────────────────────────────────────────────┘         
│          ▼                                                                     │
│  [4/5]   │ Threat Intel + Risk Analysis                                         │
│          │ ┌─────────────────────────────────────────────────────────┐         
│          │ │ threatintel.NewThreatIntelDB()                          │         
│          │ │   ├─ Built-in: KnownC2IPs (33 indicators)               │         
│          │ │   ├─ External file: -feed flag → GetFeedIOCs()          │         
│          │ │   ├─ Live: ThreatFox API → FeedCacheManager (1h TTL)    │         
│          │ │   └─ C2IntelFeeds CSV: FetchAllIOCs() (~590 indicators)│         
│          │ │                                                         │         
│          │ │ scanner.AssessConnectionRiskWithThreatIntel()           │         
│          │ │   ├─ 6 heuristics per connection                        │         
│          │ │   │   1. Suspicious port (4444, 8080, 1337, etc.)       │         
│          │ │   │   2. Suspicious process (cmd.exe, powershell, ...)  │         
│          │ │   │   3. Transition state (SYN_SENT, TIME_WAIT, ...)    │         
│          │ │   │   4. High IP connection count (>= threshold)        │         
│          │ │   │   5. High process connection count (>= threshold)   │         
│          │ │   │   6. Privilege escalation chain                     │         
│          │ │   └─ Threat intel boost (confidence >= 80 → high)      │         
│          │ └─────────────────────────────────────────────────────────┘         
│          ▼                                                                     │
│  [5/5]   │ Report + Alerting                                                    │
│          │ ┌─────────────────────────────────────────────────────────┐         
│          │ │ report.GenerateMarkdown(data, filename)                 │         
│          │ │ report.GenerateJSON(data, filename)                     │         
│          │ │ report.GenerateCSV(data, connCSV, riskCSV)              │         
│          │ │                                                         │         
│          │ │ alerting.Registry.Send() [if cfg.Alerting.Enabled]      │         
│          │ │   ├─ WebhookNotifier (HTTP POST)                        │         
│          │ │   └─ SyslogNotifier (stderr)                            │         
│          │ └─────────────────────────────────────────────────────────┘         
└──────────┴──────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Output Artifacts                                      │
│                                                                                 │
│  • network_sentinel_<hostname>_<timestamp>.md   (Markdown report)              │
│  • network_sentinel_<hostname>_<timestamp>.json  (JSON report)                 │
│  • network_sentinel_<hostname>_<timestamp>_connections.csv                    │
│  • network_sentinel_<hostname>_<timestamp>_risks.csv                          │
│  • baseline.json                               (Saved current state)          │
│  • captured_dns_queries_<hostname>_<timestamp>.json (DNS capture)             │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Module Dependency Graph

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         Module Dependency Graph                                  │
│                                                                                  │
│  main.go ──┬──► config                                                          │
│            ├──► systeminfo                                                     │
│            ├──► scanner ──────────┬──► config                                  │
│            │                       ├──► processinfo                             │
│            │                       └──► threatintel                             │
│            ├──► dns ───────────────┬──► scanner (Connection type)              │
│            │                        └──► exec.Command (platform)               │
│            ├──► baseline                                           │
│            ├──► threatintel ────────┬──► net/http (standard library)           │
│            │                        └──► encoding/csv                          │
│            ├──► report ─────────────┬──► scanner (Connection, ProcessEntry,   │
│            │                        │   ConnectionRisk, RiskLevel)             │
│            │                        ├──► baseline (DiffResult, Entry)          │
│            │                        ├──► processinfo (Info)                    │
│            │                        ├──► systeminfo (SystemDetails)            │
│            │                        ├──► dns (CaptureResult)                   │
│            │                        └──► version (Version)                     │
│            ├──► alerting                                            │
│            └──► version                                             │
│                                                                                  │
│  ui/main.go (Wails GUI) ──┬──► All of the above (same core packages)           │
│                           └──► ui/configmgr ──► config                          │
│                                                                                  │
│  c2update/main.go (standalone) ──► No internal dependencies                     │
│                                    (Self-contained HTTP + CSV parsing)          │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Core Architectural Components

### 4.1 scanner — Core Scanning Engine

**Purpose:** Orchestrate process enumeration, network connection capture, and risk assessment.

**Internal structure:**
- `scanner.go` — Shared types (`Connection`, `ProcessEntry`, `ConnectionRisk`, `RiskLevel`), heuristics, `ScanAll()`, `AssessConnectionRisk()`
- `scanner_windows.go` — `wmic process` + `netstat -ano` enumeration
- `scanner_linux.go` — `/proc/[pid]/comm` + `/proc/net/tcp{,6}` inode→PID mapping
- `scanner_darwin.go` — `ps axco pid,comm` + `lsof -nP -i` enumeration

**Key design patterns:**
- Chain of 6 heuristics with on-stack `[6]string` for zero-alloc reason collection
- Pre-computed lowercase map (`suspiciousProcsLower`) for O(1) case-insensitive process name lookups
- `determineDirection()` classifies connections as outbound/internal/inbound based on IP classification

**Extension points:**
- Add new suspicious ports to `CommonReverseProxyPorts` map
- Add new suspicious processes to `suspiciousProcsForOS()` per platform
- Add new heuristic by incrementing the reasons array and adjusting threshold logic

### 4.2 config — Configuration Management

**Purpose:** Load, validate, and provide O(1) lookup for thresholds, exclusions, whitelist, DNS, alerting, and threat intel settings.

**Key patterns:**
- `Defaults()` returns sane defaults (thresholds: 5 connections/min, critical=3, high=2)
- `Load()` merges partial JSON with defaults using pointer-typed partial struct
- `buildIPIndex()` pre-computes lowercase IP map for O(1) whitelist lookups
- Invalid entries are cleared, not crashed (defensive validation)

### 4.3 threatintel — Threat Intelligence Database

**Purpose:** In-memory IOC database with IP/domain lookup, populated from multiple sources.

**Internal structure:**
- `threatintel.go` — `ThreatIntelDB` with `ipv4`/`domain` maps, `IOC` type, `LookupConnection()`
- `feeds.go` — Built-in `KnownC2IPs` (33 indicators), `ThreatFoxFeedClient`, `FeedCacheManager`, `FeedURLClient`
- `loader.go` — JSON feed file loading (`LoadFeed()`, `GetFeedIOCs()`, `MergeFeed()`)
- `c2intelfeeds.go` — CSV parser for C2IntelFeeds repository (4 feeds, ~590 indicators)

**Key patterns:**
- Case-insensitive lookups via `strings.ToLower()` keyed maps
- TTL-based cache (`FeedCacheManager`) with stale-on-failure fallback
- Generic CSV parser with `csvFeedConfig` struct parameterizes all 3 feed types

### 4.4 processinfo — Per-Process Security Context

**Purpose:** Gather privilege level, code signing status, integrity level, and execution path for each PID.

**Internal structure:**
- `processinfo.go` — Shared types (`Info`, `AdminPrivilegeLevel`, `IntegrityLevel`, `TokenElevationType`), `IsPrivEscalation()`, `IsSuspiciousPath()`
- `processinfo_windows.go` — PowerShell script for token elevation + Authenticode signature
- `processinfo_linux.go` — `/proc/[pid]/status` + `/etc/passwd` for UID→username
- `processinfo_darwin.go` — `ps -p <pid>` + `/usr/bin/which` + `/etc/passwd`

**Key patterns:**
- `suspiciousPathPatterns` slice populated by each OS `init()` — single shared `IsSuspiciousPath()` function
- Unified `IsPrivEscalation()` method is the single source of truth for scanner and report

### 4.5 dns — DNS Resolution and Capture

**Purpose:** Parallel reverse DNS lookup and platform-specific DNS cache capture.

**Internal structure:**
- `lookup.go` — `LookupDomainsParallel()` worker pool, `ResolveConnectionsDNS()`, `CheckDomain()` (suspicious TLD + keyword detection)
- `query.go` — `Query`, `CaptureResult` types, `SaveCaptureResult()`, `DNSQueriesToIPMap()`
- `query_windows.go` — `Get-CimInstance MSFT_DNSClientCache` via PowerShell
- `query_linux.go` — `journalctl -u systemd-resolved` + `/var/log/syslog` fallback
- `query_darwin.go` — `dscacheutil -q host` + `log show` fallback

**Key patterns:**
- Channel-based worker pool with configurable concurrency
- 2s context timeout per lookup prevents DNS hangs
- Address deduplication before fan-out avoids redundant lookups

### 4.6 baseline — Snapshot Diffing

**Purpose:** Save connection snapshots and compare against previous baselines to detect new/gone connections.

**Key patterns:**
- Key-based comparison: `PID:RemoteAddr:RemotePort` unique key per connection
- `Diff()` builds bidirectional maps to classify entries as New/Gone/Unchanged
- JSON serialization for persistence

### 4.7 report — Report Generation

**Purpose:** Generate Markdown, JSON, and CSV reports from scan data.

**Key patterns:**
- `report.Data` bundles all scan results into a single struct
- `strings.Builder` for efficient Markdown construction
- `sanitizeMarkdown()` escapes `|` and backticks for safe table rendering
- `countFindings()` aggregates statistics from connections + risks + privilege escalation

### 4.8 alerting — Alert Delivery

**Purpose:** Send alerts to configured notifiers (webhook, syslog/stdout).

**Key patterns:**
- `Notifier` interface with `Name()` + `Send(alert)` — extensible for Slack, PagerDuty, etc.
- `Registry` broadcasts to all registered notifiers
- `WebhookNotifier` HTTP POST with JSON payload
- `SyslogNotifier` stderr output (cross-platform syslog simulation)

### 4.9 systeminfo — System Discovery

**Purpose:** Gather OS-level metadata (hostname, OS platform, local IPs, MAC addresses).

**Key patterns:**
- Pure Go standard library calls — no platform-specific implementation needed
- Filters loopback interfaces and non-up interfaces

### 4.10 c2update — Standalone C2Feed Updater

**Purpose:** Independent binary for scheduled C2IntelFeeds CSV updates.

**Key patterns:**
- Separate Go module with `replace` directive for `threatintel` types
- CLI flags for selective feed fetching (`-30day`, `-domain`, `-ipport`)
- Deduplication via `seen` map
- JSON envelope output with metadata

### 4.11 ui — Desktop GUI (Wails)

**Purpose:** Cross-platform desktop application wrapping the core scanning logic.

**Key patterns:**
- Wails v2 framework (Go backend + HTML/CSS/JS frontend via `embed.FS`)
- `App` struct encapsulates scan state (`lastScan`, `lastReport`, `lastBaseline`)
- Response types (`ScanResult`, `ConnectionResp`, `RiskResp`, etc.) for JSON serialization to frontend
- `configmgr` package handles config save/export/snapshot operations
- Reuses all core packages (`scanner`, `threatintel`, `baseline`, `report`, `dns`, `systeminfo`)

---

## 5. Architectural Layers and Dependencies

### 5.1 Layer Map

| Layer | Packages | Responsibility |
|-------|----------|----------------|
| Orchestration | `main.go`, `ui/main.go` | CLI flag parsing, pipeline coordination, daemon loop |
| Data Collection | `scanner`, `systeminfo`, `dns` | Process enumeration, connection capture, DNS resolution |
| Security Context | `processinfo` | Per-PID privilege, signing, integrity data |
| Intelligence | `threatintel` | IOC database, feed clients, external data aggregation |
| Analysis | `scanner` (heuristics), `dns` (domain analysis) | Risk assessment, suspicious domain detection |
| Persistence | `baseline`, `ui/configmgr` | Snapshot diffing, config management |
| Output | `report`, `alerting` | Report generation, alert delivery |
| Metadata | `version` | Version string |

### 5.2 Dependency Rules

```
main.go ──imports──► config, systeminfo, scanner, dns, threatintel, baseline, report, alerting, version
scanner ──imports──► config, processinfo, threatintel
report ──imports──► scanner, baseline, processinfo, systeminfo, dns, version
dns ──imports──► scanner (Connection type only)
config ──imports──► (none — leaf module)
threatintel ──imports──► (none — leaf module)
baseline ──imports──► (none — leaf module)
processinfo ──imports──► (none — leaf module)
alerting ──imports──► (none — leaf module)
systeminfo ──imports──► (none — leaf module)
```

**No circular dependencies.** All dependencies flow inward toward leaf modules.

---

## 6. Data Architecture

### 6.1 Core Domain Models

| Model | Key Fields | Used By |
|-------|-----------|---------|
| `Connection` | PID, Process, Local/Remote Addr:Port, Protocol, State, Direction, DNSName | scanner, report, dns, ui |
| `ProcessEntry` | PID, Name | scanner, report, ui |
| `ConnectionRisk` | Connection + RiskLevel, RiskReasons, IsSuspicious, IsWhitelisted | scanner, report, ui |
| `RiskLevel` | `"low"` \| `"medium"` \| `"high"` \| `"critical"` | scanner, report |
| `Info` (processinfo) | PID, Name, Username, ExePath, PrivLevel, IsSigned, Integrity | scanner, report, ui |
| `IOC` | Indicator, IndicatorType, MalwareFamily, Confidence, Country, Tags, Source | threatintel, c2update, ui |
| `ThreatIntelDB` | ipv4 map, domain map | scanner, main, ui |
| `Config` | Thresholds, Excluded, Whitelist, DNS, Alerting, ThreatIntel | scanner, main, ui |
| `Data` (report) | System, Connections, Processes, Risks, Security, Baseline, Whitelist, DNSQueries | report |
| `Findings` | Outbound, Endpoints, Suspicious ports/procs, Risk counts, PrivEsc, Whitelisted | report, ui |
| `Snapshot` | Timestamp, Hostname, Entries | baseline |
| `DiffResult` | New, Gone, Unchanged, BaselineAge | baseline, main, ui |
| `Alert` | Timestamp, Level, Message, Details | alerting, main |
| `Notifier` | interface { Name(), Send() } | alerting |

### 6.2 Data Flow

```
Raw OS data (wmic/netstat, /proc, lsof)
    │
    ▼
Connection[] + ProcessEntry[] + SecurityInfo[]
    │
    ├──► DNS resolution ──► DNSName populated
    ├──► Threat intel lookup ──► RiskLevel + RiskReasons
    ├──► Baseline comparison ──► DiffResult
    └──► Report.Data ──► Markdown/JSON/CSV + alerts
```

---

## 7. Cross-Cutting Concerns

### 7.1 Configuration Management

- **Source:** JSON config file (`config.json` by default), CLI flags (`-config`, `-daemon`, `-feed`, `-output`)
- **Validation:** Thresholds validated for non-negativity and ordering (critical >= high); whitelist IPs validated with `net.ParseIP()`
- **Defaults:** `config.Defaults()` provides sane values; partial JSON merges on top
- **UI snapshots:** `ui/configmgr` provides named snapshots with export/import

### 7.2 Error Handling and Resilience

- **Graceful degradation:** DNS failures logged as warnings, not fatal; threat intel fetch failures don't stop scan
- **Cache fallback:** `FeedCacheManager` returns stale cache on network errors
- **Defensive parsing:** CSV parser skips malformed rows; wmic output handles variable blank line spacing
- **Timeout enforcement:** DNS lookups have 2s context timeout; HTTP requests have configurable timeouts

### 7.3 Logging and Monitoring

- **Stdout:** Progress messages during scan (`fmt.Println()` with `[N/5]` step markers)
- **Stderr:** Alert notifications (`SyslogNotifier`), config load warnings
- **Report:** Comprehensive Markdown/JSON/CSV with all findings
- **DNS capture:** Optional JSON file with queried domains

### 7.4 Validation

- **Input validation:** `config.Load()` validates all user-provided values at load time
- **IP classification:** `scanner.IsPrivateIP()` handles IPv4 ranges, IPv6 loopback/link-local/multicast
- **Whitelist lookup:** Pre-computed index with O(1) lookup; linear scan fallback for edge cases

---

## 8. Service Communication Patterns

### 8.1 External API Integration

| Service | Protocol | Format | Auth | Retry Strategy |
|---------|----------|--------|------|----------------|
| ThreatFox | HTTPS GET | JSON | Optional API key | 10s timeout, stale cache fallback |
| C2IntelFeeds | HTTPS GET | CSV | None | 10s timeout, logged warning on failure |
| Custom feed URL | HTTPS GET | JSON | None | 10s timeout, logged warning |

### 8.2 Alert Delivery

| Notifier | Protocol | Payload |
|----------|----------|---------|
| Webhook | HTTP POST | `{"timestamp","level","message","details"}` |
| Syslog | stderr | `[timestamp] [LEVEL] stdout: message: details` |

---

## 9. Technology-Specific Patterns

### 9.1 Go-Specific Architectural Patterns

- **Build tags for platform abstraction:** `//go:build windows`, `linux`, `darwin` swap implementations at compile time
- **`init()` for platform-specific data injection:** `suspiciousPathPatterns` slice populated by OS-specific `init()` functions
- **Pre-computed lookup maps:** `suspiciousProcsLower` built in `init()` for O(1) case-insensitive process name checks
- **On-stack arrays for zero allocation:** `[6]string` in `AssessConnectionRisk` avoids heap when no heuristics fire
- **`strings.Builder` for report generation:** Efficient string construction without intermediate allocations
- **Embed for UI assets:** `//go:embed all:frontend/dist` bundles frontend assets into the Go binary

---

## 10. Implementation Patterns

### 10.1 Interface Design

- **`Notifier` interface:** Minimal contract (`Name()` + `Send(alert)`) enables adding Slack, PagerDuty, email without modifying existing code
- **`suspiciousProcsForOS()` function:** Returns map per platform; shared code calls via `SuspiciousProcessNamesList()`

### 10.2 Service Composition

- **`AssessConnectionRiskWithThreatIntel()`:** Wraps `AssessConnectionRisk()`, then enriches results with threat intel matches
- **`FeedCacheManager`:** Wraps `ThreatFoxFeedClient`, adds TTL caching and stale-on-failure semantics

### 10.3 Generic CSV Parser

`parseCSVFeed()` in `c2intelfeeds.go` uses a `csvFeedConfig` struct to parameterize:
- Column count
- Header skip
- Confidence column index
- Tags, source, port column indices

Three feed types (IP, IP+port, domain) each delegate to the same parser with different configs, eliminating ~90 lines of duplicated parsing logic.

---

## 11. Testing Architecture

| Package | Test File | Approach |
|---------|-----------|----------|
| `scanner` | `scanner_test.go`, `scanner_bench_test.go` | Unit tests + benchmarks |
| `config` | `config_test.go` | Config loading, validation, whitelist lookup |
| `dns` | `lookup_test.go`, `query_test.go` | DNS resolution, domain analysis |
| `threatintel` | `threatintel_test.go`, `loader_test.go` | IOC database, feed loading |
| `baseline` | `baseline_test.go` | Snapshot save/load/diff |
| `report` | `report_test.go` | Report generation |
| `alerting` | `alerting_test.go` | Alert delivery |
| `processinfo` | `processinfo_test.go` | Security context gathering |
| `version` | `version_test.go` | Version string |

**Coverage command:** `go test ./... -coverprofile=c.out && go tool cover -func c.out`

---

## 12. Deployment Architecture

### 12.1 Build Targets

| Target | Command | Output |
|--------|---------|--------|
| Windows | `go build -o networksentinel.exe .` | `networksentinel.exe` |
| Linux | `GOOS=linux go build -o networksentinel .` | `networksentinel` |
| macOS | `GOOS=darwin go build -o networksentinel .` | `networksentinel` |
| UI (Windows) | `wails build` | Native app with embedded frontend |
| UI (Linux) | `wails build` | Native app with embedded frontend |

### 12.2 Scheduled Updates

```bash
# Linux/macOS cron (every 6 hours)
0 */6 * * * /path/to/c2update.sh -output /path/to/c2intel_feeds.json >> /var/log/c2update.log 2>&1

# Windows Task Scheduler (daily at 2 AM)
schtasks /create /tn "C2IntelFeedsUpdate" /tr "powershell -ExecutionPolicy Bypass -File c2update.ps1" /sc daily /st 02:00

# systemd timer (6h interval with 30min jitter)
sudo cp c2update.timer c2update.service /etc/systemd/system/
sudo systemctl enable --now c2update.timer
```

### 12.3 Daemon Mode

```bash
# Continuous scanning every 300 seconds
./networksentinel -daemon 300
```

---

## 13. Extension and Evolution Patterns

### 13.1 Adding a New Suspicious Port

1. Add port number to `CommonReverseProxyPorts` map in `scanner/scanner.go`
2. No code changes needed — `IsSuspiciousPort()` already iterates the map

### 13.2 Adding a New Suspicious Process (per platform)

1. Add process name to `suspiciousProcsForOS()` in the platform-specific file (`scanner_windows.go`, `_linux.go`, or `_darwin.go`)
2. No shared code changes — `init()` pre-computes the lowercase map automatically

### 13.3 Adding a New Heuristic

1. Add the check in `AssessConnectionRisk()` before the risk level assignment
2. Increment the reasons array usage (max 6 heuristics currently)
3. If more than 6 heuristics needed, switch from `[6]string` to `make([]string, 0, 10)`

### 13.4 Adding a New Alert Notifier

1. Implement `Notifier` interface (`Name()` + `Send(alert)`)
2. Register in `main.go` or `ui/main.go` via `reg.AddNotifier(&MyNotifier{})`

### 13.5 Adding a New Threat Intel Feed Source

1. Create a new feed client type (like `ThreatFoxFeedClient`) that returns `[]IOC`
2. Add fetch logic in `main.go`'s `runScan()` before `AssessConnectionRiskWithThreatIntel()`
3. Call `tiDB.AddIOCs(newIOCs)` to merge into the database

### 13.6 Adding a New Report Format

1. Add a new function `GenerateXXX(data Data, filename string) error` in `report/report.go`
2. Call it from `main.go`'s `runScan()` alongside existing report generators

---

## 14. Blueprint for New Development

### 14.1 Development Workflow

**For a new feature (e.g., new heuristic):**

1. **Shared types** → Add to `scanner.go` (if new types needed)
2. **Platform-specific logic** → Add to `scanner_windows.go`, `_linux.go`, `_darwin.go` with build tags
3. **Heuristic integration** → Add to `AssessConnectionRisk()` in `scanner.go`
4. **Report integration** → Add to `GenerateMarkdown()` in `report/report.go`
5. **Tests** → Add to `scanner_test.go`, `report_test.go`
6. **Build** → `go build -o networksentinel.exe .`
7. **Test** → `go test ./...`

### 14.2 Component Creation Templates

**New platform-specific file:**
```go
//go:build windows (or linux, darwin)

package scanner

func enumerateProcesses() ([]ProcessEntry, error) {
    // Platform-specific implementation
}

func getNetConnections(connSet map[int]*Connection) ([]Connection, error) {
    // Platform-specific implementation
}

func suspiciousProcsForOS() map[string]struct{} {
    return map[string]struct{}{
        "your-process": {},
    }
}
```

**New alert notifier:**
```go
package alerting

type MyNotifier struct {
    URL string
}

func (m *MyNotifier) Name() string { return "my-notifier" }

func (m *MyNotifier) Send(alert Alert) error {
    // Implementation
    return nil
}
```

### 14.3 Common Pitfalls

| Pitfall | Prevention |
|---------|------------|
| Modifying slice in range loop | Use `for i := range conns { c := &conns[i] }` to modify elements |
| DNS timeout without context | Always wrap `net.Resolver` with `context.WithTimeout(2s)` |
| Invalid whitelist IP crash | Use `net.ParseIP()` validation at load time; clear invalid entries |
| Markdown table injection | Escape `|` and backticks with `sanitizeMarkdown()` |
| Extra `)` in `strings.Builder` | Verify after editing — easy to double-parenthesize |
| go.mod patch version | Use `go 1.26` not `go 1.26.2` in `go.mod` |
| IPv6 bracket notation | Strip `[` and `]` before IP prefix matching |
| wmic blank line spacing | Use emit-on-both-fields strategy, not blank-counting |
| Global state | Never use package-level variables for config; pass `*config.Config` |
| CGo on Windows | Use `exec.Command` + PowerShell; never `CGO_ENABLED=1` |

---

## 15. Architecture Governance

### 15.1 Consistency Enforcement

- **Build tags:** Platform-specific files must use correct `//go:build` tags
- **No global state:** Enforced by project rules in `AGENTS.md`
- **Typed constants:** Use `RiskLevel` string type, not bare strings
- **Explicit interfaces:** `Notifier` interface, not ad-hoc function signatures

### 15.2 Automated Checks

```bash
# Build verification (required after every code change)
go build -o networksentinel.exe .

# Test suite (all packages must pass)
go test ./...

# Per-function coverage
go test ./... -coverprofile=c.out && go tool cover -func c.out
```

---

*This blueprint was generated on 2026-06-05 from analysis of the `networksentinel` Go module. Review and update this document when significant architectural changes are made.*
