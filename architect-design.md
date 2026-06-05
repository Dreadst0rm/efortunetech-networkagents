# NetworkSentinel — Architecture & End-to-End Flow

## Entry Point: `main.go`

`main.go` is the orchestrator. It parses CLI flags, loads config, then runs either:
- **One-shot scan** (`runScan()`) — single analysis pass
- **Daemon mode** (`runDaemon()`) — continuous scanning on a timer

Both paths call `runScan()`, which executes a 5-step pipeline.

---

## Pipeline Overview

```
main.go
  │
  ├─ [1/5] System Info   → systeminfo.Gather()
  │
  ├─ [2/5] Scan           → scanner.ScanAll(cfg)
  │                          ├─ enumerateProcesses()    (platform-specific)
  │                          ├─ getNetConnections()     (platform-specific)
  │                          ├─ correlate PID → process name
  │                          ├─ determineDirection()    (outbound/internal/inbound)
  │                          ├─ filter excluded PIDs/processes
  │                          └─ processinfo.GetProcessInfo(pid)  (security context)
  │
  ├─ DNS Resolution       → dns.LookupDomain(remoteAddr)
  │
  ├─ [3/5] Baseline Diff  → baseline.Load() + baseline.Diff()
  │
  ├─ [4/5] Risk Analysis  → scanner.AssessConnectionRisk()
  │                          └─ threatintel.AssessConnectionRiskWithThreatIntel()
  │
  └─ [5/5] Report         → report.GenerateMarkdown()
                              report.GenerateJSON()
                              report.GenerateCSV()
                              alerting.Registry.Send()  (if enabled)
```

---

## Step-by-Step: What Each File Does

### 1. `systeminfo/systeminfo.go` — System Discovery

**Purpose:** Gather OS-level metadata about the host.

**What it does:**
- Calls `os.Hostname()` to get the machine name
- Reads `runtime.GOOS` for the OS platform string (e.g., `"windows"`, `"linux"`, `"darwin"`)
- Iterates `net.Interfaces()` to collect all non-loopback IPv4 addresses

**Returns:** `*SystemDetails` — hostname, OS platform, list of local IPs.

**Called by:** `main.go` at step [1/5]. The result is passed into the report as system context.

---

### 2. `config/config.go` — Configuration Management

**Purpose:** Load, validate, and merge user config with built-in defaults.

**What it does:**
- `Defaults()` returns a `Config` struct with sane defaults (thresholds: 5 connections/min, critical=3, high=2)
- `Load(filename)` reads a JSON config file, merges it with defaults
- Validates thresholds (no negatives, critical >= high)
- Validates whitelist IPs using `net.ParseIP()` — clears invalid entries
- Provides helper methods: `IsExcludedPID()`, `IsExcludedProcess()`, `IsWhitelistedIP()`, `GetWhitelistComment()`

**Key types:**
- `Config` — top-level config (thresholds, exclusions, whitelist, DNS log, alerting)
- `Thresholds` — numeric thresholds for heuristics
- `WhitelistedIP` — IP + comment pair

**Called by:** `main.go` at the very start. Passed throughout the pipeline to `scanner.ScanAll()`, `scanner.AssessConnectionRisk()`, and `report` generation.

---

### 3. `scanner/scanner.go` — Core Scanning Logic (Shared Types + Heuristics)

**Purpose:** Define shared types, risk heuristics, and orchestrate platform-specific scanning.

**What it does:**
- **`ScanAll(cfg)`** — The main scanning entry point. Orchestrates the full scan:
  1. Calls `enumerateProcesses()` (platform-specific, from `scanner_windows.go`/`_linux.go`/`_darwin.go`)
  2. Calls `getNetConnections()` (platform-specific)
  3. Correlates connections to process names via PID
  4. Determines connection direction (outbound/internal/inbound)
  5. Filters excluded PIDs/processes from config
  6. Gathers security context via `processinfo.GetProcessInfo()` for each unique PID

- **`AssessConnectionRisk(conns, secInfo, cfg)`** — Evaluates 6 heuristics per outbound connection:
  1. Suspicious port (C2/proxy ports like 4444, 8080, 1337)
  2. Suspicious process name (cmd.exe, powershell.exe, etc.)
  3. Anomalous TCP state (SYN_SENT, TIME_WAIT, CLOSE_WAIT, SYN_RECEIVED)
  4. High connection count to same IP (>= `MinIPConnections`)
  5. High outbound connection count per process (>= `MinProcessConnections`)
  6. Privilege escalation chain (elevated + unsigned + temp path)

  Assigns risk level: Medium (1 reason), High (>= `HighThreshold`), Critical (>= `CriticalThreshold`).

- **`AssessConnectionRiskWithThreatIntel()`** — Wraps `AssessConnectionRisk()`, then enriches results with threat intel matches (boosts risk level based on IOC confidence).

- **`IsPrivateIP()`, `IsExternalIP()`** — IP classification helpers.

- **`IsSuspiciousPort()`, `IsTransitionState()`, `IsSuspiciousProcess()`** — Individual heuristic checks.

**Key types:**
- `Connection` — a single network connection (PID, process name, local/remote addr:port, protocol, state, direction, DNS name)
- `ConnectionRisk` — a `Connection` annotated with risk level, reasons, and whitelist status
- `ProcessEntry` — a process (PID + name) from enumeration
- `RiskLevel` — string type: `"low"`, `"medium"`, `"high"`, `"critical"`
- `CommonReverseProxyPorts` — map of known suspicious ports

**Called by:** `main.go` at steps [2/5] and [4/5]. Returns data to the report.

---

### 4. `scanner/scanner_windows.go` — Windows Platform Scanner

**Purpose:** Enumerate processes and network connections on Windows.

**What it does:**
- `enumerateProcesses()` — Runs `wmic process get Name,ProcessId /format:list`, parses the output format (Name=xxx / ProcessId=1234 separated by blank lines), returns `[]ProcessEntry`
- `getNetConnections(connSet)` — Runs `netstat -ano`, parses Active Connections table, extracts protocol, local/remote addr:port, state, PID. Handles IPv4 and IPv6 with bracket notation.
- `parseWindowsAddr(s)` — Splits `addr:port`, strips IPv6 brackets
- `suspiciousProcsForOS()` — Returns Windows-specific suspicious process names (cmd.exe, powershell.exe, wmic.exe, certutil.exe, etc.)

**Build tag:** `//go:build windows`

---

### 5. `scanner/scanner_linux.go` — Linux Platform Scanner

**Purpose:** Enumerate processes and connections on Linux via `/proc`.

**What it does:**
- `enumerateProcesses()` — Reads `/proc/[pid]/comm` for each numeric PID directory, skips PIDs <= 2
- `getNetConnections()` — Builds inode->PID map from `/proc/[pid]/fd/*` symlinks, then parses `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`
- `parseProcNetTCP()` / `parseProcNetUDP()` — Converts hex addresses to readable IPs, maps TCP state codes (01=ESTABLISHED, 02=SYN_SENT, etc.) to names, correlates to PIDs via inode
- `hexToTCPAddr(s)` — Converts hex IP:port from `/proc/net/*` to `*net.TCPAddr`. Handles both IPv4 (8 hex chars, network byte order) and IPv6 (32 hex chars, 8 hextets of 4 hex chars each)
- `suspiciousProcsForOS()` — Returns Linux-specific suspicious process names (bash, sh, python, nc, netcat, curl, wget, ssh, sudo, nmap, tcpdump, etc.)

**Build tag:** `//go:build linux`

---

### 6. `scanner/scanner_darwin.go` — macOS Platform Scanner

**Purpose:** Enumerate processes and connections on macOS.

**What it does:**
- `enumerateProcesses()` — Runs `ps axco pid,comm`, parses output skipping header
- `getNetConnections()` — Runs `lsof -nP -i`, parses output for process name, PID, local/remote addr:port, state
- `parseAddr(s)` — Splits `addr:port`, handles IPv6 brackets
- `suspiciousProcsForOS()` — Returns macOS-specific suspicious process names (similar to Linux: bash, sh, python, nc, curl, wget, ssh, sudo, nmap, etc.)

**Build tag:** `//go:build darwin`

---

### 7. `processinfo/processinfo.go` — Security Context Types (Shared)

**Purpose:** Define types for per-PID security context.

**What it does:**
- `Info` struct — carries per-PID security data: PID, name, username, exe path, privilege level, isSystem, integrity level, signer, isSigned, token elevation type
- `AdminPrivilegeLevel` — `"elevated"`, `"standard"`, `"system"`
- `TokenElevationType` — `Full`, `Limited`, `Default` (integer values 1, 2, 0)
- `IntegrityLevel` — `System`, `High`, `Medium`, `Low` (integer values 3, 2, 1, 0)

**Called by:** `scanner.ScanAll()` which calls `processinfo.GetProcessInfo(pid)` for each unique PID. The returned `map[int]Info` is passed to `AssessConnectionRisk()` for privilege escalation detection.

---

### 8. `processinfo/processinfo_windows.go` — Windows Security Context

**Purpose:** Gather per-PID security context on Windows via PowerShell.

**What it does:**
- `GetProcessInfo(pid)` — Runs a PowerShell script that queries:
  - Process name via `Get-Process -Id <pid>`
  - Executable path via `$proc.MainModule.FileName`
  - User context via `Get-CimInstance Win32_Process`
  - Code signing status via `Get-AuthenticodeSignature`
  - Privilege level and integrity level (derived from token elevation)
- Parses tab-separated output, returns `Info` struct
- `IsProcessElevated()`, `IsProcessUnsigned()`, `IsSuspiciousPath()` — Helper checks for privilege escalation detection

**Build tag:** `//go:build windows`

---

### 9. `processinfo/processinfo_linux.go` — Linux Security Context

**Purpose:** Gather per-PID security context on Linux via `/proc`.

**What it does:**
- `GetProcessInfo(pid)` — Reads `/proc/[pid]/exe` for executable path, `/proc/[pid]/status` for UID/EUID
- Resolves UID to username via `/etc/passwd`
- Sets privilege level based on euid (0=root, 1-999=system user, 1000+=regular user)
- `IsProcessElevated()`, `IsProcessUnsigned()`, `IsSuspiciousPath()` — Helper checks for privilege escalation detection

**Build tag:** `//go:build linux`

---

### 10. `processinfo/processinfo_darwin.go` — macOS Security Context

**Purpose:** Gather per-PID security context on macOS via `ps` and `/etc/passwd`.

**What it does:**
- `GetProcessInfo(pid)` — Runs `ps -p <pid> -o comm=,uid=` for process name and UID
- Resolves UID to username via `/etc/passwd`
- Resolves process name to executable path via `/usr/bin/which`
- Sets privilege level based on UID (0=root, 1-999=system user, 1000+=regular user)
- `IsProcessElevated()`, `IsProcessUnsigned()`, `IsSuspiciousPath()` — Helper checks for privilege escalation detection

**Build tag:** `//go:build darwin`

---

### 11. `threatintel/threatintel.go` — Threat Intelligence Database

**Purpose:** In-memory C2 indicator database with IP/domain lookup.

**What it does:**
- `NewThreatIntelDB()` — Creates empty DB with `ipv4` and `domain` maps
- `AddIOC(ioc)` / `AddIOCs(iocs)` — Adds indicators to the appropriate map by type
- `LookupIP(ip)` — Returns matching IOCs for an IP address
- `LookupDomain(domain)` — Returns matching IOCs for a domain
- `LookupConnection(remoteAddr)` — Tries IP lookup first, then domain
- `Count()` — Returns total indicator count

**Key types:**
- `IOC` — Indicator of compromise: indicator string, type, malware family, first/last seen, country, confidence (0-100), tags, source, status, port
- `MatchResult` — Result of a lookup: indicator, matching IOCs, count

**Called by:** `main.go` at step [4/5]. The DB is populated with built-in C2 indicators (`KnownC2IPs`) and optionally loaded from an external feed file.

---

### 12. `threatintel/feeds.go` — Built-in C2 Indicators

**Purpose:** Hardcoded C2 IP addresses and phishing domains from threat intelligence sources.

**What it does:**
- `KnownC2IPs` — Slice of 33 `IOC` structs covering Cobalt Strike, Metasploit, Empire, Sliver, BruteRatel, LummaStealer, MeduzaStealer, QuasarRAT, DarkComet, njRAT, RemcosRAT, PoisonIvy, AsyncRAT, ShadowPad, Covenant, Mythic, Deimos, Havoc, Caldera, and 11 phishing domains
- Each IOC has metadata: malware family, confidence (72-95), country, tags, source (ThreatFox)

**Called by:** `main.go` at step [4/5] via `tiDB.AddIOCs(threatintel.KnownC2IPs)`.

---

### 13. `threatintel/loader.go` — External Feed Loading

**Purpose:** Load C2 indicators from external JSON feed files.

**What it does:**
- `LoadFeed(filename)` — Reads JSON file, unmarshals into `[]IOC`, returns populated `ThreatIntelDB`
- `GetFeedIOCs(filename)` — Returns raw `[]IOC` from a feed file
- `MergeFeed(db, iocs)` — Merges loaded indicators into an existing DB
- `FeedCount(filename)` — Returns indicator count from a feed file

**Called by:** `main.go` at step [4/5] via `threatintel.GetFeedIOCs(*feedFile)` when `-feed` flag is provided.

---

### 14. `dns/lookup.go` — DNS Forward Lookup

**Purpose:** Resolve IP addresses to domain names via reverse DNS lookup.

**What it does:**
- `LookupDomain(addr)` — Forward DNS lookup via `net.Resolver` with 2s timeout, resolves an IP address to a domain name
- `CheckDomain(domain)` — Analyzes a domain for suspicious indicators. Checks:
  - Suspicious TLDs (`.tk`, `.xyz`, `.top`, `.online`, `.club`, `.store`, `.site`, `.work`, `.trade`, `.info`, `.biz`)
  - Keyword matches (login, verify, secure, auth, account, signin, banking, payment, crypto, wallet, admin)
  - Returns confidence score (0-100) and reason string

**Key types:**
- `SuspiciousDomainResult` — domain, confidence, isSuspicious, reason

**Called by:** `main.go` at step [2/5] for DNS resolution on outbound connections.

---

### 15. `dns/query_windows.go` / `query_linux.go` / `query_darwin.go` — Platform-Specific DNS Capture

**Purpose:** Capture DNS cache entries from OS-specific sources.

**What they do:**
- **Windows** (`query_windows.go`): Uses `Get-CimInstance MSFT_DNSClientCache` via PowerShell to get DNS cache entries, parses JSON output for domain/process correlation
- **Linux** (`query_linux.go`): Uses `journalctl -u systemd-resolved --grep query` first, then falls back to `/var/log/syslog` for DNS query logs
- **macOS** (`query_darwin.go`): Uses `dscacheutil -q host -a name` first, then falls back to `log show --predicate "eventMessage CONTAINS 'DNS'"` for DNS query logs

**Build tags:** `//go:build windows`, `//go:build linux`, `//go:build darwin` respectively.

---

### 16. `dns/query.go` — DNS Query Types & Utilities

**Purpose:** Define types and utilities for DNS query logging.

**What it does:**
- `Query` struct — captured DNS query: PID, query name, timestamp
- `CaptureResult` — result of DNS capture: timestamp, hostname, queries list, capture method, suspicious results
- `SaveCaptureResult(result, filename)` — saves DNS queries to JSON file

**Called by:** `main.go` at step [DNS] when `cfg.DNSLog` is enabled.

---

### 17. `baseline/baseline.go` — Snapshot Diffing

**Purpose:** Save connection snapshots and compare against previous baselines.

**What it does:**
- `Save(filename, hostname, entries)` — Marshals `Snapshot{Timestamp, Hostname, Entries}` to JSON
- `Load(filename)` — Reads and unmarshals a baseline JSON file
- `Diff(current, baseline)` — Compares current connections against a previous snapshot:
  - Builds maps keyed by `ProcessID:RemoteAddr:RemotePort`
  - Classifies entries as New, Gone, or Unchanged
  - Calculates baseline age

**Key types:**
- `Entry` — single connection in baseline (PID, process, local/remote addr:port, state)
- `Snapshot` — timestamped collection of entries
- `DiffResult` — New, Gone, Unchanged lists + baseline age

**Called by:** `main.go` at step [3/5]. If a previous baseline exists, it's loaded and compared. After the scan, the current state is saved as the new baseline.

---

### 18. `report/report.go` — Report Generation

**Purpose:** Generate Markdown, JSON, and CSV reports from scan data.

**What it does:**
- `GenerateMarkdown(data, filename)` — Writes a comprehensive Markdown report with sections:
  - System Information (hostname, OS, local IPs)
  - Network Connections Summary (total, outbound, inbound, connection states)
  - External Endpoints (unique IP:port pairs with DNS names)
  - Suspicious Connections (table of flagged connections)
  - Risk Analysis Summary (critical/high/medium/low counts)
  - Whitelisted Connections (with admin comments)
  - Top Processes by Network Activity (top 20 by connection count)
  - Privilege Escalation Analysis (elevated + unsigned processes)
  - Baseline Comparison (new/gone/unchanged)
  - Key Findings (summary table)
- `GenerateJSON(data, filename)` — Writes structured JSON with all scan data, findings summary, DNS lookup count
- `GenerateCSV(data, connFile, riskFile)` — Writes two CSV files: connections and risks
- `IsExternal(c)` — Delegates to `scanner.IsExternalIP()`
- `IsSuspicious(c)` — Returns true if connection target is external (not local/private)
- `IsLocal(addr)` — Delegates to `scanner.IsPrivateIP()`
- `IsSuspiciousProcess(name)` — Checks against `scanner.SuspiciousProcessNamesList()`
- `Summarize(data)` -> `Findings` — Counts: total outbound, external endpoints, suspicious ports, suspicious processes, risk level counts, privilege escalation count, whitelisted count
- `countFindings()` — Internal helper for `Summarize()`
- `isSuspiciousPort(port)` — Delegates to `scanner.IsSuspiciousPort()`
- `sanitizeMarkdown(s)` — Escapes `|` and `` ` `` for safe Markdown table rendering

**Key types:**
- `Data` — bundles all scan data: System, Connections, Processes, Risks, Security, Baseline, Whitelist
- `Findings` — summary counts (outbound, endpoints, suspicious ports/procs, risk counts, priv esc, whitelisted)
- `WhitelistedIP` — IP + comment for report rendering

**Called by:** `main.go` at step [5/5].

---

### 19. `alerting/alerting.go` — Alert Delivery

**Purpose:** Send alerts to configured notifiers (webhook, syslog/stdout).

**What it does:**
- `Alert` struct — timestamp, level, message, details
- `Notifier` interface — `Name()` + `Send(alert)`
- `WebhookNotifier` — HTTP POST to configured URL with JSON payload
- `SyslogNotifier` — Writes to stderr (cross-platform syslog simulation)
- `Registry` — Manages multiple notifiers, broadcasts alerts to all

**Called by:** `main.go` after risk analysis. If `cfg.Alerting.Enabled` is true, creates a registry, adds webhook notifier (if URL configured) and stdout notifier, then sends alerts for Critical and High risk connections.

---

### 20. `version/version.go` — Version String

**Purpose:** Provides the application version string.

**What it does:**
- `Version` constant — e.g., `"1.0.0"`

**Called by:** `main.go` for banner display and report metadata.

---

## Data Flow Diagram

```
+------------------------------------------------------------------+
|                      main.go (Orchestrator)                      |
|                                                                  |
|  1. Parse CLI flags                                             |
|  2. config.Load("config.json")                                   |
|  3. If daemon mode -> runDaemon() -> loop(runScan())            |
|  4. Else -> runScan()                                           |
|                                                                  |
|  runScan():                                                      |
|    [1/5] systeminfo.Gather()                                    |
|      -> hostname, OS, local IPs                                  |
|    [2/5] scanner.ScanAll(cfg)                                   |
|      -> enumerateProcesses()  (platform-specific)                |
|      -> getNetConnections()   (platform-specific)                |
|      -> correlate PID -> process name                            |
|      -> determineDirection()                                     |
|      -> filter excluded                                          |
|      -> processinfo.GetProcessInfo(pid)                          |
|    DNS: dns.LookupDomain(remoteAddr)                             |
|    [3/5] baseline.Load() + baseline.Diff()                       |
|    [4/5] scanner.AssessConnectionRisk()                          |
|      -> 6 heuristics per connection                              |
|      -> threatintel.LookupConnection()                           |
|    [5/5] report.GenerateMarkdown() / GenerateJSON() / CSV()      |
|    alerting.Registry.Send() (if enabled)                         |
|    baseline.Save()                                               |
+------------------------------------------------------------------+
```

---

## Module Dependencies

```
main.go
  +-- config (Load)
  +-- systeminfo (Gather)
  +-- scanner (ScanAll, AssessConnectionRisk, AssessConnectionRiskWithThreatIntel)
  +-- dns (LookupDomain, CaptureDNSQueries, CheckDomain, SaveCaptureResult)
  +-- threatintel (NewThreatIntelDB, AddIOCs, GetFeedIOCs)
  +-- baseline (Load, Diff, Save)
  +-- report (GenerateMarkdown, GenerateJSON, GenerateCSV, IsSuspicious, IsExternal, IsLocal, Summarize)
  +-- alerting (NewRegistry, AddNotifier, Send)
  +-- version (Version)

scanner
  +-- config (IsExcludedPID, IsExcludedProcess, IsWhitelistedIP, Thresholds)
  +-- processinfo (GetProcessInfo, Info, Elevated, SYSTEM, IsSuspiciousPath)
  +-- threatintel (ThreatIntelDB, LookupConnection)

report
  +-- scanner (IsExternalIP, IsPrivateIP, SuspiciousProcessNamesList, IsSuspiciousPort, Connection, ProcessEntry, ConnectionRisk, RiskLevel)
  +-- baseline (DiffResult, Entry)
  +-- processinfo (Info, Elevated, SYSTEM)
  +-- systeminfo (SystemDetails)
  +-- version (Version)

processinfo
  +-- (no internal dependencies)

dns
  +-- (platform-specific: uses exec.Command for OS tools)

alerting
  +-- (no internal dependencies)

baseline
  +-- (no internal dependencies)

config
  +-- (no internal dependencies)

threatintel
  +-- (no internal dependencies)

systeminfo
  +-- (no internal dependencies)

version
  +-- (no internal dependencies)
```

---

## Key Design Patterns

1. **Platform abstraction via build tags** — Each OS has its own implementation file (`_windows.go`, `_linux.go`, `_darwin.go`). The shared code in `scanner.go` and `processinfo.go` compiles across all platforms.

2. **Dependency injection** — `config.Config` is passed throughout the pipeline, allowing all modules to access thresholds, exclusions, and whitelist without global state.

3. **Chain of heuristics** — `AssessConnectionRisk()` applies 6 independent checks, then aggregates reasons to determine risk level. Each heuristic is a pure function that can be tested independently.

4. **Data bundling** — `report.Data` aggregates all scan results into a single struct, making it easy to pass to report generators without complex parameter lists.

5. **Interface-based alerting** — `Notifier` interface allows adding new alert delivery mechanisms (Slack, PagerDuty, etc.) without modifying existing code.
