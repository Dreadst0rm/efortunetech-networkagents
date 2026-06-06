# NetworkSentinel — Project Architecture Blueprint

> **Generated:** 2026-06-05
> **Module:** `networksentinel` v0.4.0
> **Language:** Go 1.26
> **Architecture Pattern:** Layered Monolith with Cross-Platform Abstraction

---

## 1. Architecture Detection and Analysis

### Technology Stack

| Category | Technology |
|----------|-----------|
| Language | Go 1.26 |
| External dep | `github.com/miekg/dns` v1.1.62 (DNS resolution) |
| Indirect deps | `golang.org/x/net`, `golang.org/x/sync`, `golang.org/x/sys`, `golang.org/x/mod`, `golang.org/x/tools` |
| Platform APIs | Windows: `wmic`, `netstat`, PowerShell 5.1, WinToken P/Invoke |
| Platform APIs | Linux: `/proc/PID/`, `journalctl`, `syslog` |
| Platform APIs | macOS: `ps`, `lsof`, `dscacheutil`, `log` |
| Build | `go build` with `//go:build` tags for cross-compilation |
| CI/CD | GitHub Actions (Windows/Linux/macOS matrix + golangci-lint) |

### Detected Architectural Patterns

1. **Layered Architecture** — Clear separation: orchestrator (main) → data collection (scanner) → analysis (risk assessment + threat intel) → output (report + alerting)
2. **Platform Abstraction via Build Tags** — Shared types in `scanner.go`, `processinfo.go`, `dns/query.go`; platform-specific IO in `_windows.go`, `_linux.go`, `_darwin.go` files
3. **Pipeline / Workflow Pattern** — 5-phase scan pipeline in `runScan()`: system info → scan → baseline → threat intel + risk → report
4. **Heuristic Scoring System** — Multi-heuristic risk assessment (6 independent signals) with configurable thresholds
5. **Composite Pattern** — `report.Data` bundles all data sources into a single struct for report generation
6. **Cache Pattern** — `FeedCacheManager` with TTL-based caching for live threat intel feeds

---

## 2. Architectural Overview

NetworkSentinel is a **single-binary, cross-platform security monitoring tool** that performs network process analysis to detect suspicious outbound connections, C2 communication, privilege escalation, and anomalous behavior.

### Guiding Principles

1. **No CGo on Windows** — All platform-specific operations use `exec.Command` with native utilities (PowerShell, wmic, netstat, ps, lsof), never CGo
2. **Cross-platform first** — Every subsystem has 3 implementations (Windows/Linux/macOS) via `//go:build` tags
3. **Multi-heuristic risk scoring** — No single-factor detection; each connection is evaluated on 6 independent signals
4. **Configuration-driven thresholds** — Risk levels are configurable; defaults are conservative
5. **Zero external dependencies for core functionality** — Only `miekg/dns` for DNS resolution; all other data comes from OS utilities

### Architectural Boundaries

- **`config`** — No internal dependencies; pure configuration loading and validation
- **`baseline`** — No internal dependencies; JSON snapshot + diff
- **`systeminfo`** — No internal dependencies; simple hostname/OS/IP gathering
- **`version`** — No internal dependencies; single version string
- **`alerting`** — No internal dependencies; pluggable notification interfaces
- **`threatintel`** — No internal dependencies; in-memory IOC database + HTTP feed clients
- **`processinfo`** — No internal dependencies; per-PID security context
- **`scanner`** → depends on → `config`, `processinfo`, `threatintel`
- **`dns`** → depends on → `config`, `scanner`, `github.com/miekg/dns`
- **`report`** → depends on → `baseline`, `dns`, `processinfo`, `scanner`, `systeminfo`, `version`
- **`main`** → depends on → everything (orchestrator)

---

## 3. Architecture Visualization

### System Context (C4 Level 1)

```
┌──────────────────────────────────────────────────────────┐
│                    Host Machine                          │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │           NetworkSentinel Binary                 │     │
│  │                                                  │     │
│  │  ┌──────────┐  ┌───────────┐  ┌───────────────┐ │     │
│  │  │  Scanner │──▶│  DNS      │  │ ThreatIntel   │ │     │
│  │  └──────────┘  └───────────┘  └───────────────┘ │     │
│  │       │            │                │            │     │
│  │  ┌──────────┐  ┌───────────┐  ┌───────────────┐ │     │
│  │  │ Process  │  │ Report    │  │ Alerting      │ │     │
│  │  │ Info     │  │ Generator │  │ Registry      │ │     │
│  │  └──────────┘  └───────────┘  └───────────────┘ │     │
│  │       │            │                              │     │
│  │  ┌──────────┐  ┌───────────┐                     │     │
│  │  │ Config   │  │ Baseline  │                     │     │
│  │  └──────────┘  └───────────┘                     │     │
│  └─────────────────────────────────────────────────┘     │
│                                                          │
│  External: OS utilities (wmic, netstat, ps, lsof, ...)   │
│  External: DNS resolver (miekg/dns)                      │
│  External: ThreatFox API, C2IntelFeeds (HTTP)            │
└──────────────────────────────────────────────────────────┘
```

### Component Level (C4 Level 2)

```
┌───────────────────────────────────────────────────────────────────┐
│                        main.go (Orchestrator)                     │
│                                                                   │
│  ┌───────────┐   ┌──────────┐   ┌───────────┐   ┌─────────────┐ │
│  │ systeminfo│──▶│ scanner  │──▶│ dns       │   │ threatintel │ │
│  └───────────┘   └──────────┘   └───────────┘   └─────────────┘ │
│       │              │                │               │           │
│       │         ┌──────────┐    ┌──────────┐    ┌────▼────────┐  │
│       │         │processinfo│    │ baseline │    │ alerting    │  │
│       │         └──────────┘    └──────────┘    └─────────────┘  │
│       │              │                │           │               │
│       └──────────────▼────────────────▼───────────┘               │
│                          │                                        │
│                    ┌───────────┐                                   │
│                    │ report    │                                   │
│                    └───────────┘                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Data Flow (Scan Pipeline)

```
[1] systeminfo.Gather()
    ├── Hostname, OS, Local IPs
    └── → output: *SystemDetails

[2] scanner.ScanAll(cfg)
    ├── enumerateProcesses()     → []ProcessEntry
    ├── getNetConnections()      → []Connection
    ├── Correlate(PID)           → Connection.Process, Connection.Direction
    ├── Filter(excluded)         → filtered connections
    └── processinfo.GetProcessInfo(PID) → map[int]Info

    dns.ResolveConnectionsDNS()  → Connection.DNSName (populated)

[3] baseline.Load("baseline.json")
    ├── baseline.Diff()          → DiffResult{New, Gone, Unchanged}

[4] threatintel.NewThreatIntelDB()
    ├── AddIOCs(KnownC2IPs)      → 32 built-in indicators
    ├── GetFeedIOCs(feedFile)    → external feed indicators
    ├── cacheMgr.GetIOCs()       → live ThreatFox indicators
    ├── c2Client.FetchAllIOCs()  → C2IntelFeeds CSV indicators
    └── → ThreatIntelDB (all indicators merged)

    scanner.AssessConnectionRiskWithThreatIntel()
    ├── 6 heuristics per connection
    │   ├── suspicious port
    │   ├── suspicious process
    │   ├── transition state
    │   ├── high per-IP count
    │   ├── high per-process count
    │   └── privilege escalation chain
    ├── threat intel match       → confidence-based risk upgrade
    └── → []ConnectionRisk

[5] report.GenerateMarkdown()/JSON()/CSV()
    ├── Data{System, Connections, Processes, Risks, Security, Baseline, ...}
    └── → Markdown, JSON, CSV files

alerting.NewRegistry()
    ├── WebhookNotifier          → HTTP POST
    └── SyslogNotifier           → stdout
```

---

## 4. Core Architectural Components

### 4.1 Scanner (`scanner/`)

**Purpose:** Core network and process enumeration engine with multi-heuristic risk assessment.

**Internal Structure:**
- `scanner.go` — Shared types (`Connection`, `ProcessEntry`, `ConnectionRisk`, `RiskLevel`), risk assessment logic (`AssessConnectionRisk`, `AssessConnectionRiskWithThreatIntel`), heuristic functions
- `scanner_windows.go` — Windows: `wmic process` + `netstat -ano` parsing
- `scanner_linux.go` — Linux: `/proc/net/tcp{,6}` + inode-to-PID mapping via `/proc/net/tcp`
- `scanner_darwin.go` — macOS: `ps axco pid,comm` + `lsof -nP -i`

**Key Patterns:**
- **Platform abstraction** via `//go:build` tags with interface functions (`enumerateProcesses`, `getNetConnections`, `suspiciousProcsForOS`)
- **Composite scoring** — 6 heuristics per connection, threshold-based risk level assignment
- **O(1) lookups** — `suspiciousProcsLower` pre-computed map for process name checks; `cfg.IsWhitelistedIP` uses pre-built `ipIndex`

**Interaction:**
- Consumed by `main.go` (scan orchestration) and `report.go` (suspicious detection)
- Depends on `config`, `processinfo`, `threatintel`

---

### 4.2 Process Info (`processinfo/`)

**Purpose:** Per-PID security context collection for privilege escalation detection.

**Internal Structure:**
- `processinfo.go` — Shared types (`Info`, `AdminPrivilegeLevel`, `IntegrityLevel`, `TokenElevationType`), cross-platform helpers (`IsSuspiciousPath`, `uidToUsername`)
- `processinfo_windows.go` — Windows: PowerShell token elevation + `Get-AuthenticodeSignature`
- `processinfo_linux.go` — Linux: `/proc/PID/exe` + `/proc/PID/status` + `/etc/passwd`
- `processinfo_darwin.go` — macOS: `ps` + `which`

**Key Types:**
```go
type Info struct {
    PID       int
    Name      string
    Username  string
    ExePath   string
    PrivLevel AdminPrivilegeLevel  // "elevated", "standard", "system"
    IsSystem  bool
    Integrity IntegrityLevel       // system/high/medium/low
    Signer    string
    IsSigned  bool
    TokenElev TokenElevationType   // full/limited/default
}
```

**Interaction:**
- Consumed by `scanner.ScanAll()` → returns `map[int]Info`
- Used in `report.GenerateMarkdown()` for privilege escalation section

---

### 4.3 DNS Resolution (`dns/`)

**Purpose:** Domain name resolution and DNS cache capture for connection enrichment.

**Internal Structure:**
- `query.go` — DNS cache capture (platform-specific), domain suspicion analysis (`CheckDomain`), `CaptureResult`
- `lookup.go` — Reverse DNS (PTR), forward DNS (A), parallel lookups, `ResolveConnectionsDNS`
- `miekg_dns.go` — `DNSSession` wrapper around `miekg/dns`, parallel query execution
- `query_windows.go` — Windows: `Get-DnsClientCache` PowerShell cmdlet
- `query_linux.go` — Linux: `journalctl` + `syslog` parsing
- `query_darwin.go` — macOS: `dscacheutil` + `log` command

**Key Patterns:**
- **Shared session** — `dnsSession` package-level variable created in `init()`, reused across all lookups
- **Parallel queries** — `QueryMultiplePTRs`, `QueryMultipleDomains` for concurrent DNS resolution
- **Graceful degradation** — Fallback to connection-based DNS resolution when cache capture fails

**Interaction:**
- Consumed by `main.go` (DNS capture + cross-reference), `report.go` (DNS section)
- Depends on `config`, `scanner`

---

### 4.4 Threat Intelligence (`threatintel/`)

**Purpose:** In-memory IOC database with multi-source indicator aggregation.

**Internal Structure:**
- `threatintel.go` — `ThreatIntelDB` (in-memory IOC store), `IOC` struct, IP/domain lookup
- `feeds.go` — `KnownC2IPs` (32 built-in indicators), `ThreatFoxFeedClient`, `FeedCacheManager`, `FeedURLClient`
- `loader.go` — JSON feed file loading

**Key Patterns:**
- **Composite data source** — Built-in + file feed + live API + CSV feed, all merged into single DB
- **Cache with TTL** — `FeedCacheManager` with mutex-protected cache, stale-fallback-on-error
- **Confidence-based escalation** — IOC confidence ≥90 → critical; ≥80 → high (if not already higher)

---

### 4.5 Report Generator (`report/`)

**Purpose:** Multi-format report generation from scan data.

**Internal Structure:**
- `report.go` — Single file (572 lines): `GenerateMarkdown`, `GenerateJSON`, `GenerateCSV`, `countFindings`, `Summarize`

**Key Data Structure:**
```go
type Data struct {
    System      *systeminfo.SystemDetails
    Connections []scanner.Connection
    Processes   []scanner.ProcessEntry
    Risks       []scanner.ConnectionRisk
    Security    map[int]processinfo.Info
    Baseline    baseline.DiffResult
    Whitelist   []WhitelistedIP
    DNSQueries  *dns.CaptureResult
}
```

**Output Formats:**
- **Markdown** — Human-readable report with tables for each section
- **JSON** — Full structured data with `Findings` summary
- **CSV** — Separate files for connections and risks

---

### 4.6 Configuration (`config/`)

**Purpose:** Configuration loading, validation, and O(1) whitelist lookup.

**Key Patterns:**
- **Defaults + partial merge** — `Defaults()` provides built-in values; `Load()` merges JSON overlay
- **Pre-computed index** — `buildIPIndex()` creates `ipIndex` map for O(1) whitelist lookups
- **Input validation** — `net.ParseIP()` rejects invalid whitelist entries at load time; threshold clamping

---

### 4.7 Alerting (`alerting/`)

**Purpose:** Pluggable alert delivery system.

**Key Types:**
```go
type Registry struct {
    notifiers []Notifier
}

type Notifier interface {
    Send(alert Alert) error
}
```

**Implementations:**
- `WebhookNotifier` — HTTP POST to configurable URL
- `SyslogNotifier` — stdout with syslog-like formatting

---

### 4.8 Baseline (`baseline/`)

**Purpose:** Connection snapshot save/load and diff for change tracking.

**Key Functions:**
- `Save(filename, hostname, entries)` — JSON snapshot
- `Load(filename)` — JSON snapshot load
- `Diff(current, previous)` — `DiffResult{New, Gone, Unchanged, BaselineAge}`

---

### 4.9 System Info (`systeminfo/`)

**Purpose:** Simple hostname, OS platform, and local IP gathering.

---

### 4.10 C2 Updater (`c2update/`)

**Purpose:** Standalone binary for scheduled C2 indicator feed refresh.

**Flow:** Parse CLI → Fetch CSV feeds from C2IntelFeeds GitHub → Parse/deduplicate → Write JSON envelope

---

## 5. Architectural Layers and Dependencies

### Layer Map

| Layer | Packages | Role |
|-------|----------|------|
| **Orchestrator** | `main` | Pipeline coordination, CLI, daemon mode |
| **Data Collection** | `scanner`, `processinfo`, `systeminfo` | OS-level data gathering |
| **Enrichment** | `dns` | DNS resolution, cache capture |
| **Analysis** | `threatintel` | IOC matching, risk scoring |
| **Output** | `report`, `alerting` | Report generation, notifications |
| **Support** | `config`, `baseline`, `version` | Configuration, snapshots, version |

### Dependency Rules

```
main → config, scanner, processinfo, threatintel, dns, report, baseline, systeminfo, version, alerting

scanner → config, processinfo, threatintel

report → baseline, dns, processinfo, scanner, systeminfo, version

dns → config, scanner, miekg/dns

threatintel → (none internal)

processinfo → (none internal)

config → (none internal)

baseline → (none internal)

alerting → (none internal)

systeminfo → (none internal)

version → (none internal)
```

**No circular dependencies.** Pure layered architecture with support packages at the bottom.

---

## 6. Data Architecture

### Domain Model

```
Connection {
    ProcessID  int
    Process    string
    Executable string
    LocalAddr  string
    LocalPort  int
    RemoteAddr string
    RemotePort int
    Protocol   string
    State      string
    Direction  string    // "outbound" | "inbound" | "internal" | "unknown"
    DNSName    string    // resolved domain name
}

ProcessEntry {
    PID  int
    Name string
}

ConnectionRisk {
    Connection
    RiskLevel     RiskLevel  // "low" | "medium" | "high" | "critical"
    RiskReasons   []string
    IsSuspicious  bool
    IsWhitelisted bool
}

Info (processinfo) {
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

IOC {
    Indicator     string
    IndicatorType string  // "ipv4" | "domain" | "url"
    MalwareFamily string
    FirstSeen     time.Time
    LastSeen      time.Time
    Country       string
    Confidence    int      // 0-100
    Tags          []string
    Source        string
    Status        string
    Port          int
}
```

### Data Transformation

1. **Raw OS output** → `Connection` / `ProcessEntry` (scanner parsers)
2. **Connection + Process correlation** → enriched `Connection` (PID → process name)
3. **Connection + DNS** → `Connection.DNSName` populated
4. **Connection + heuristics + threat intel** → `ConnectionRisk`
5. **All data** → `report.Data` → Markdown/JSON/CSV

### Caching

- **DNS session** — Package-level `dnsSession` reused across all lookups
- **Threat intel cache** — `FeedCacheManager` with 1-hour TTL, mutex-protected

---

## 7. Cross-Cutting Concerns Implementation

### Error Handling & Resilience

- **Graceful degradation** — Every external call (DNS, threat intel feeds, baseline load) has error handling that logs a warning but continues
- **Fallback patterns** — `FeedCacheManager.GetIOCs()` returns stale cache on fetch error; DNS fallback to connection-based resolution
- **No retry logic** — Single-attempt calls with error logging; appropriate for short-lived diagnostic tool

### Configuration Management

- **JSON config** — `config.json` with optional overlay on built-in defaults
- **CLI flags** — `-config`, `-output`, `-daemon`, `-feed`, `-h`
- **Validation** — Threshold clamping, IP validation at load time, concurrency defaults
- **Feature toggles** — `dns_log`, `alerting.enabled`, `threat_intel.enabled`

### Logging & Monitoring

- **Stdout console output** — Progress indicators (`[1/5]`, `[2/5]`), summary statistics
- **Warning logging** — `log.Printf` for non-fatal errors (feed fetch failures, baseline save errors)
- **No structured logging** — Simple `log` package usage; no log files or external aggregation

---

## 8. Service Communication Patterns

### External APIs

| Service | Protocol | Purpose | Resilience |
|---------|----------|---------|------------|
| ThreatFox API | HTTP GET | Live C2 indicators | Timeout (10s), cache with TTL, stale fallback |
| C2IntelFeeds | HTTP GET (CSV) | Cobalt Strike indicators | Timeout, error logged, continues |
| Custom feed URL | HTTP GET | User-provided IOC feed | Timeout, error logged, continues |

### Internal Communication

- **Direct function calls** — No event bus, no message queues, no async channels between packages
- **Data passing** — All data passed explicitly through function parameters
- **Daemon mode** — `time.Ticker` + `context.WithCancel` for periodic scan loops

---

## 9. Go-Specific Architectural Patterns

### Build Tag Pattern

```go
//go:build windows

package scanner
```

Each platform-specific file implements the same interface functions:
- `enumerateProcesses() ([]ProcessEntry, error)`
- `getNetConnections(connSet map[int]*Connection) ([]Connection, error)`
- `suspiciousProcsForOS() map[string]struct{}`

### Package-Level Initialization

```go
var dnsSession *DNSSession

func init() {
    s, err := NewDNSSession()
    if err != nil {
        dnsSession = nil
    } else {
        dnsSession = s
    }
}
```

Shared resources created once at package init, reused across all operations.

### Pre-computed Indexes for Performance

```go
var suspiciousProcsLower map[string]struct{}

func init() {
    suspiciousProcsLower = make(map[string]struct{})
    for n := range suspiciousProcsForOS() {
        suspiciousProcsLower[strings.ToLower(n)] = struct{}{}
    }
}
```

O(1) case-insensitive process name lookups instead of O(n) linear scans.

### Stack-Allocated Buffers

```go
var reasons [6]string
count := 0
// ... reasons[count] = "..."
count++
```

Avoids heap allocation in hot path; max 6 heuristics.

---

## 10. Implementation Patterns

### Multi-Heuristic Scoring

Each outbound connection is evaluated on 6 independent signals:

```
count = 0
if suspicious_port → count++
if suspicious_process → count++
if transition_state → count++
if ip_count >= threshold → count++
if process_count >= threshold → count++
if priv_escalation → count++

switch count:
    >= critical_threshold → critical
    >= high_threshold     → high
    == 1                 → medium
    == 0                 → skip (no risk)
```

### Threat Intel Confidence Escalation

```
if ioc.Confidence >= 90:
    risk_level = RiskCritical
elif ioc.Confidence >= 80:
    if risk_level in (RiskLow, RiskMedium):
        risk_level = RiskHigh
```

### Platform-Independent Interface

```go
// In scanner.go (shared):
func enumerateProcesses() ([]ProcessEntry, error)  // declared, implemented per-OS
func getNetConnections(map[int]*Connection) ([]Connection, error)  // declared, implemented per-OS
func suspiciousProcsForOS() map[string]struct{}  // declared, implemented per-OS
```

The shared file references these functions; the build tag files provide implementations.

---

## 11. Testing Architecture

### Test Coverage

| Package | Test File | Lines | Coverage |
|---------|-----------|-------|----------|
| `scanner` | `scanner_test.go` | 948 | Core logic, heuristics, direction detection, risk assessment |
| `report` | `report_test.go` | 839 | Report generation for all formats |
| `threatintel` | `loader_test.go` | 564 | Feed file loading, JSON parsing |
| `threatintel` | `threatintel_test.go` | 203 | IOC database, lookups |
| `processinfo` | `processinfo_test.go` | 426 | Privilege levels, path detection |
| `config` | `config_test.go` | 288 | Config loading, validation, whitelist |
| `dns` | `lookup_test.go` | 178 | DNS resolution, parallel lookups |
| `dns` | `query_test.go` | 73 | Domain suspicion analysis |
| `baseline` | `baseline_test.go` | 113 | Snapshot save/load, diff |
| `alerting` | `alerting_test.go` | 45 | Registry, notifier sending |
| `systeminfo` | `systeminfo_test.go` | 33 | Hostname, OS, IPs |
| `version` | `version_test.go` | 11 | Version string |

**Total:** ~5,300 lines of tests across 12 test files.

### Test Strategy

- **Unit tests** — All packages have unit tests with table-driven tests
- **No integration tests** — Tests avoid real OS calls; use mocks/tables for scanner/dns
- **Benchmarks** — `scanner_bench_test.go`, `dns/lookup_test.go` for performance validation
- **CI matrix** — Tests run on Windows/Linux/macOS across Go 1.21–1.23

---

## 12. Deployment Architecture

### Deployment Targets

| Platform | Binary | Size | Build Command |
|----------|--------|------|---------------|
| Windows | `networksentinel.exe` | ~10 MB | `go build -o networksentinel.exe .` |
| Linux | `networksentinel_linux` | ~3.8 MB | `GOOS=linux go build -tags netgo -o networksentinel_linux .` |
| macOS | `networksentinel_darwin` | ~4 MB | `GOOS=darwin go build -tags netgo -o networksentinel_darwin .` |

### Deployment Models

1. **Single-shot scan** — Default mode; runs once and exits
2. **Daemon mode** — `--daemon <seconds>`; continuous periodic scanning
3. **Scheduled C2 update** — `c2update.service` + `c2update.timer` (systemd); `c2update.ps1` (Windows Task Scheduler)
4. **Standalone binary** — Self-contained; no runtime dependencies beyond OS utilities

### Environment Adaptations

- **No environment variables** — All configuration via `config.json` and CLI flags
- **Platform-specific paths** — Baseline file `baseline.json` in working directory; no fixed paths
- **No containerization** — Designed for direct host execution; no Dockerfile

---

## 13. Extension and Evolution Patterns

### Adding a New Platform

1. Create `scanner_<os>.go` implementing `enumerateProcesses()`, `getNetConnections()`, `suspiciousProcsForOS()`
2. Create `processinfo_<os>.go` implementing `GetProcessInfo(pid int) (Info, error)`
3. Create `query_<os>.go` implementing `CaptureDNSQueries(cfg *config.Config, hostname string) (*CaptureResult, error)`
4. Add to build tags: `//go:build <os>`

### Adding a New Heuristic

1. Add detection logic in `scanner.AssessConnectionRisk()` → `reasons[count] = "..."`
2. Increment `count`
3. No threshold changes needed if new heuristic is binary (fires or doesn't)
4. If heuristic produces a score, may need threshold adjustments

### Adding a New Alert Channel

1. Implement `alerting.Notifier` interface:
```go
type MyNotifier struct{}

func (n *MyNotifier) Send(alert alerting.Alert) error {
    // send alert
    return nil
}
```
2. Register in `main.go`:
```go
reg.AddNotifier(&MyNotifier{})
```

### Adding a New Feed Source

1. Create feed client in `threatintel/feeds.go` (similar to `ThreatFoxFeedClient`)
2. Instantiate and call in `main.go` `runScan()`:
```go
myClient := NewMyFeedClient(timeout)
myIOCs, _ := myClient.FetchIOCs()
tiDB.AddIOCs(myIOCs)
```

---

## 14. Architecture Governance

### Consistency Mechanisms

1. **Build tag enforcement** — Go compiler enforces platform abstraction; missing OS file causes build failure
2. **CI/CD matrix** — Tests run on all 3 platforms; cross-compilation verified
3. **golangci-lint** — Static analysis in CI
4. **AGENTS.md** — Development guidelines and lessons learned in repo root

### Documentation Practices

- **README.md** — User-facing documentation
- **Platform guides** — `windows-guide.md`, `linux-guide.md`, `macos-guide.md`
- **architect-design.md** — Architecture design document
- **AGENTS.md** — Development rules and lessons learned

---

## 15. Blueprint for New Development

### Development Workflow

#### Adding a New Feature (e.g., new detection type)

1. **Define types** in shared file (e.g., `scanner.go`)
2. **Implement platform-specific IO** in `_<os>.go` files with build tags
3. **Add to pipeline** in `main.go` or relevant package
4. **Add tests** in `_test.go` file
5. **Build and test** on all platforms: `go test ./...`

#### Adding a New Report Section

1. Add fields to `report.Data` struct
2. Add section generation in `GenerateMarkdown()`
3. Add to `GenerateJSON()` if needed
4. Add to `Summarize()` if counting is needed
5. Add tests in `report_test.go`

### Implementation Templates

#### New Platform-Specific File Template

```go
//go:build <os>

package <package>

func <interfaceFunction>() (<returnType>, error) {
    // Implement using native OS utilities
    // Use exec.Command for PowerShell/Bash calls
    // Never use CGo
}
```

#### New Package Template

```go
package <name>

// No internal dependencies unless explicitly required
// Keep package focused on single responsibility
```

### Common Pitfalls

1. **Mixing debug and refactor** — Isolate changes to one phase at a time
2. **Adding CGo on Windows** — Use `exec.Command` with PowerShell/native utilities
3. **Slice modification in range loops** — Use `for i := range conns { c := &conns[i] }` to modify elements
4. **DNS without timeout** — Always wrap DNS calls with `context.WithTimeout(2s)`
5. **Invalid whitelist IPs at runtime** — Validate at config load time with `net.ParseIP()`
6. **Markdown table injection** — Escape `|` and `` ` `` in user-provided strings
7. **Double-parentheses in strings.Builder** — Easy to accidentally add extra `)` in `sb.WriteString()` calls
8. **wmic blank line parsing** — Fields separated by 1 blank line, entries by 3+ consecutive blank lines; use emit-on-field strategy

### When This Blueprint Was Generated

**Date:** 2026-06-05
**Version:** 0.4.0

### Keeping This Blueprint Updated

- Review and update after each major feature addition
- Update dependency table when adding external packages
- Update platform abstraction section when adding new OS support
- Review architecture patterns when codebase grows beyond current scope
