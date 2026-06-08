# NetworkSentinel — Architecture & End-to-End Flow

> **Last updated:** 2026-06-05 (post-UI integration, miekg/dns migration, DNS capture pipeline)

## Entry Point: `main.go`

`main.go` is the orchestrator. It parses CLI flags, loads config, then runs either:
- **One-shot scan** (`runScan()`) — single analysis pass
- **Daemon mode** (`runDaemon()`) — continuous scanning on a timer

Both paths call `runScan()`, which executes an **8-step pipeline** (previously 5 steps).

---

## Pipeline Overview

```
main.go
  │
  ├─ [1/8] System Info   → systeminfo.Gather()
  │
  ├─ [2/8] Scan           → scanner.ScanAll(cfg)
  │                          ├─ enumerateProcesses()    (platform-specific)
  │                          ├─ getNetConnections()     (platform-specific)
  │                          ├─ correlate PID → process name
  │                          ├─ determineDirection()    (outbound/internal/inbound)
  │                          ├─ filter excluded PIDs/processes
  │                          └─ processinfo.GetProcessInfo(pid) × unique PIDs
  │                              → Returns map[int]processinfo.Info (security context)
  │
  ├─ [3/8] DNS Resolution → dns.ResolveConnectionsDNS(conns, concurrency)
  │                          ├─ miekg/dns DNSSession (Google DNS 8.8.8.8:53)
  │                          ├─ QueryMultiplePTRs() concurrent reverse lookups
  │                          ├─ Default 10 concurrent lookups (cfg.DNS.LookupConcurrency)
  │                          └─ Populates c.DNSName on outbound connections
  │
  ├─ [4/8] DNS Capture    → dns.CaptureDNSQueries(cfg, hostname) [if cfg.DNSLog]
  │                          ├─ Platform-specific DNS cache capture (see §16 below)
  │                          ├─ For each external connection: dns.CheckDomain() analysis
  │                          ├─ Save to JSON file (captured_dns_queries_*.json)
  │                          └─ dns.DNSQueriesToIPMap() → cross-reference to connections
  │
  ├─ [5/8] Baseline Diff  → baseline.Load() + baseline.Diff()
  │                          ├─ Key: PID:RemoteAddr:RemotePort
  │                          └─ Classifies: New, Gone, Unchanged
  │
  ├─ [6/8] Threat Intel   → Multi-source IOC aggregation
  │  ├─ Built-in: threatintel.KnownC2IPs (33 indicators)
  │  ├─ External file: -feed flag → threatintel.GetFeedIOCs()
  │  ├─ Live ThreatFox: cfg.ThreatIntel.Enabled → NewThreatFoxFeedClient()
  │  │   └─ HTTP GET https://threatfox-api.abuse.ch/v1/search (optional API key)
  │  │   └─ FeedCacheManager with 1h TTL, returns stale cache on failure
  │  └─ C2IntelFeeds CSV: NewC2IntelFeedsClient().FetchAllIOCs()
  │      └─ Fetches IPC2s.csv, IPPortC2s.csv, domainC2s.csv from GitHub
  │      └─ ~180 IPs + ~180 IP+port + ~70 domains = ~590 indicators
  │      └─ Standalone c2update binary also fetches same feeds for scheduled updates
  │          └─ Consumed via -feed flag: networksentinel -feed c2intel_feeds.json
  │
  ├─ [7/8] Risk Analysis  → scanner.AssessConnectionRiskWithThreatIntel()
  │                          ├─ 6 heuristics per outbound connection
  │                          ├─ Threat intel enrichment (boosts risk level)
  │                          └─ Returns []ConnectionRisk with risk level + reasons
  │
  └─ [8/8] Report & Alert → report.GenerateMarkdown() / GenerateJSON() / GenerateCSV()
                               alerting.Registry.Send()  (if enabled)
                               baseline.Save()
                               Print suspicious connections (if any)
                               Print top 10 processes by network activity
```

---

## Step-by-Step: What Each File Does

### 1. `systeminfo/systeminfo.go` — System Discovery

**Purpose:** Gather OS-level metadata about the host.

**What it does:**
- Calls `os.Hostname()` to get the machine name
- Reads `runtime.GOOS` for the OS platform string (e.g., `"windows"`, `"linux"`, `"darwin"`)
- Iterates `net.Interfaces()` to collect all non-loopback IPv4 addresses
- Filters interfaces by `net.FlagUp` and `net.FlagLoopback` flags

**Returns:** `*SystemDetails` — hostname, OS platform, list of local IPs, MAC addresses.

**Called by:** `main.go` at step [1/8]. The result is passed into the report as system context and to `dns.CaptureDNSQueries()`.

---

### 2. `config/config.go` — Configuration Management

**Purpose:** Load, validate, and merge user config with built-in defaults.

**What it does:**
- `Defaults()` returns a `Config` struct with sane defaults (thresholds: 5 connections/min, critical=3, high=2)
- `Load(filename)` reads a JSON config file, merges it with defaults
- Validates thresholds (no negatives, critical >= high)
- Validates whitelist IPs using `net.ParseIP()` — clears invalid entries
- Builds an in-memory `ipIndex` map for O(1) whitelist lookups
- Validates DNS concurrency (default 10) and threat intel timeout (default 10s)
- Provides helper methods: `IsExcludedPID()`, `IsExcludedProcess()`, `IsWhitelistedIP()`, `GetWhitelistComment()`

**Key types:**
- `Config` — top-level config (thresholds, exclusions, whitelist, DNS, alerting, threat intel)
- `Thresholds` — numeric thresholds for heuristics
- `DNSConfig` — DNS lookup concurrency setting (`lookup_concurrency`, default 10)
- `ThreatIntelConfig` — live feed settings: `Enabled`, `RefreshIntvl`, `APIKey`, `Timeout`, `FeedURL`
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
  6. Privilege escalation chain (elevated + unsigned + temp path) — via `privEscReason()` helper

  Uses an on-stack `[6]string` array for reasons (zero heap allocation when no heuristics fire).
  Assigns risk level: Medium (1 reason), High (>= `HighThreshold`), Critical (>= `CriticalThreshold`).

- **`AssessConnectionRiskWithThreatIntel()`** — Wraps `AssessConnectionRisk()`, then enriches results with threat intel matches (boosts risk level based on IOC confidence).

- **`IsPrivateIP()`, `IsExternalIP()`** — IP classification helpers.

- **`IsSuspiciousPort()`, `IsTransitionState()`, `IsSuspiciousProcess()`** — Individual heuristic checks.
  - `IsSuspiciousProcess()` uses a pre-computed lowercase map (`suspiciousProcsLower`) for O(1) lookups.

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

**Purpose:** Define types for per-PID security context and shared privilege escalation detection.

**What it does:**
- `Info` struct — carries per-PID security data: PID, name, username, exe path, privilege level, isSystem, integrity level, signer, isSigned, token elevation type
- `AdminPrivilegeLevel` — `"elevated"`, `"standard"`, `"system"`
- `TokenElevationType` — `Full`, `Limited`, `Default` (integer values 1, 2, 0)
- `IntegrityLevel` — `System`, `High`, `Medium`, `Low` (integer values 3, 2, 1, 0)
- `IsPrivEscalation()` method — checks if process has elevated privilege + unsigned binary + suspicious path (single source of truth for scanner + report)
- `IsSuspiciousPath()` — shared function using `suspiciousPathPatterns` slice populated by each OS-specific `init()`
- `suspiciousPathPatterns` — global slice populated by OS-specific `init()` functions with platform-specific suspicious path patterns

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
- `IsProcessElevated()`, `IsProcessUnsigned()` — Helper checks for privilege escalation detection
- `init()` — Populates `suspiciousPathPatterns` with Windows-specific patterns (`appdata\local\temp`, `\tmp\`, `users\public\`)

**Build tag:** `//go:build windows`

---

### 9. `processinfo/processinfo_linux.go` — Linux Security Context

**Purpose:** Gather per-PID security context on Linux via `/proc`.

**What it does:**
- `GetProcessInfo(pid)` — Reads `/proc/[pid]/exe` for executable path, `/proc/[pid]/status` for UID/EUID
- Resolves UID to username via `/etc/passwd`
- Sets privilege level based on euid (0=root, 1-999=system user, 1000+=regular user)
- `IsProcessElevated()`, `IsProcessUnsigned()` — Helper checks for privilege escalation detection
- `init()` — Populates `suspiciousPathPatterns` with Linux-specific patterns (`/tmp/`, `/var/tmp/`)

**Build tag:** `//go:build linux`

---

### 10. `processinfo/processinfo_darwin.go` — macOS Security Context

**Purpose:** Gather per-PID security context on macOS via `ps` and `/etc/passwd`.

**What it does:**
- `GetProcessInfo(pid)` — Runs `ps -p <pid> -o comm=,uid=` for process name and UID
- Resolves UID to username via `/etc/passwd`
- Resolves process name to executable path via `/usr/bin/which`
- Sets privilege level based on UID (0=root, 1-999=system user, 1000+=regular user)
- `IsProcessElevated()`, `IsProcessUnsigned()` — Helper checks for privilege escalation detection
- `init()` — Populates `suspiciousPathPatterns` with macOS-specific patterns (`/private/tmp/`, `/tmp/`, `/var/folders/`)

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

### 13. `threatintel/c2intelfeeds.go` — C2IntelFeeds CSV Parser

**Purpose:** Fetch and parse C2 indicators from the [drb-ra/C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) CSV repository.

**What it does:**
- `C2IntelFeedsClient` — HTTP client for fetching CSV feeds from GitHub raw URLs
- `FetchAllIOCs()` — Fetches all 4 feeds concurrently: `IPC2s.csv`, `IPPortC2s.csv`, `domainC2s.csv`, `IPC2s-30day.csv`
- `Fetch30DayIOCs()` — Fetches only the 30-day active IP list
- `fetchFeed(url, parser)` — Generic HTTP fetch with parser injection; shared by all feed fetchers
- `parseCSVFeed(r, cfg)` — Single generic CSV parser using `csvFeedConfig` struct (records, header skip, confidence, tags, source, port column)
- `parseIPFeed()`, `parseIPPortFeed()`, `parseDomainFeed()` — Thin wrappers delegating to `parseCSVFeed()` with platform-specific configs
- `detectMalwareFamily(desc)` — Maps CSV descriptions to malware family names (CobaltStrike, C2Fronting, etc.)
- Constants: `C2IntelFeedsURL`, `C2IntelFeeds30DayURL`, `C2IntelFeedsIPPortURL`, `C2IntelFeedsDomainURL`

**Feeds fetched:**
| Feed | URL | Format | Count |
|---|---|---|---|
| IPC2s.csv | Full IP C2 list | `#ip,ioc` | ~180 Cobalt Strike IPs |
| IPC2s-30day.csv | 30-day active | `#ip,ioc` | Recently active IPs |
| IPPortC2s.csv | IP+port C2 | `#ip,port,ioc` | IPs with C2 ports (443, 8080, 4444, etc.) |
| domainC2s.csv | Domain C2 | `#domain,ioc` | ~70 Cobalt Strike domains |

**Called by:** `main.go` at step [4/5] via `NewC2IntelFeedsClient().FetchAllIOCs()`. Merged into `tiDB` alongside built-in and live feeds.

---

### 14. `threatintel/loader.go` — External Feed Loading

**Purpose:** Load C2 indicators from external JSON feed files.

**What it does:**
- `LoadFeed(filename)` — Reads JSON file, unmarshals into `[]IOC`, returns populated `ThreatIntelDB`
- `GetFeedIOCs(filename)` — Returns raw `[]IOC` from a feed file
- `MergeFeed(db, iocs)` — Merges loaded indicators into an existing DB
- `FeedCount(filename)` — Returns indicator count from a feed file

**Called by:** `main.go` at step [4/5] via `threatintel.GetFeedIOCs(*feedFile)` when `-feed` flag is provided.

---

### 15. `dns/lookup.go` — DNS Resolution & Capture Integration

**Purpose:** Resolve IP addresses to domain names and capture DNS query logs.

**What it does:**
- **`ResolveConnectionsDNS(conns, concurrency)`** — Resolves outbound connection IPs to domain names:
  - Uses `DNSSession.QueryMultiplePTRs()` (miekg/dns, Google DNS 8.8.8.8:53)
  - Collects unique outbound addresses, fan-outs N concurrent lookups
  - Deduplicates addresses before lookups
  - Populates `c.DNSName` for resolved connections
  - Returns count of resolved domains
- **`DNSQueriesToIPMap(queries)`** — Builds IP→domain map from captured DNS queries for cross-referencing
- **`ResolveDomainToIP(domain)`** — Forward DNS lookup (domain → IP)
- **`resolveConnectionDomains(conns)`** — Fallback resolver for connections without DNS names
- **`CheckDomain(domain)`** — Analyzes a domain for suspicious indicators:
  - Suspicious TLDs (pre-sorted `suspiciousTLDSorted` slice for cache-friendly iteration)
  - Keyword matches (login, verify, secure, auth, account, signin, banking, payment, crypto, wallet, admin)
  - Returns `SuspiciousDomainResult` with confidence score (0-100) and reason string

**Key types:**
- `DNSSession` — miekg/dns client wrapper (see §15a below)
- `DNSCacheEntry` — cached DNS cache entry from OS
- `LookupResult` — addr + resolved name pair
- `SuspiciousDomainResult` — domain, confidence, isSuspicious, reason

**Called by:** `main.go` at step [3/8] via `dns.ResolveConnectionsDNS(conns, cfg.DNS.LookupConcurrency)`. Uses concurrency from `cfg.DNS.LookupConcurrency` (default 10).

---

### 15a. `dns/miekg_dns.go` — miekg/dns DNS Session

**Purpose:** Replace Go's `net.Resolver` with miekg/dns for more reliable DNS lookups.

**What it does:**
- `NewDNSSession()` — Creates a DNS client using Google DNS 8.8.8.8:53
- `QueryDomain(domain)` — Forward DNS lookup (domain → IP)
- `QueryDomainPTR(ip)` — Reverse DNS lookup (IP → domain)
- `QueryMultipleDomains(domains)` — Concurrent forward lookups with error handling
- `QueryMultiplePTRs(ips)` — Concurrent reverse lookups with error handling

**Why the change:** Go's `net.Resolver` had unreliable reverse DNS resolution on Windows. miekg/dns provides direct DNS protocol queries with better error handling and timeout control.

**Build tag:** No build tag — shared across all platforms.

---

### 16. `dns/query_windows.go` / `query_linux.go` / `query_darwin.go` — Platform-Specific DNS Capture

**Purpose:** Capture DNS cache entries from OS-specific sources, with miekg/dns fallback.

**What they do:**
- **Windows** (`query_windows.go`): Uses `Get-DnsClientCache` via PowerShell (updated from `Get-CimInstance MSFT_DNSClientCache` which was removed in Windows 10/11). Parses JSON output for domain/process correlation. `CaptureMethod` = `"powershell_dnsclientcache"` or `"powershell_dnsclientcache_failed"`
- **Linux** (`query_linux.go`): Uses `journalctl -u systemd-resolved --grep query` first, then falls back to `/var/log/syslog`. If both yield nothing, falls back to miekg/dns PTR lookups. `CaptureMethod` = `"journalctl_or_syslog"`
- **macOS** (`query_darwin.go`): Uses `dscacheutil -q host -a name` first, then falls back to `log show --predicate "eventMessage CONTAINS 'DNS'"`. If both yield nothing, falls back to miekg/dns PTR lookups. `CaptureMethod` = `"dscacheutil_or_log"`

**Build tags:** `//go:build windows`, `//go:build linux`, `//go:build darwin` respectively.

**New in latest version:** miekg/dns fallback added to Linux and macOS when native tools yield no results. Windows always uses PowerShell `Get-DnsClientCache`.

---

### 17. `dns/query.go` — DNS Query Types & Utilities

**Purpose:** Define types and utilities for DNS query logging.

**What it does:**
- `Query` struct — captured DNS query: PID, query name, timestamp
- `CaptureResult` — result of DNS capture: timestamp, hostname, queries list, capture method, suspicious results
- `SaveCaptureResult(result, filename)` — saves DNS queries to JSON file

**Called by:** `main.go` at step [DNS] when `cfg.DNSLog` is enabled.

---

### 18. `baseline/baseline.go` — Snapshot Diffing

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

### 19. `report/report.go` — Report Generation

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
  - Privilege Escalation Analysis (elevated + unsigned + suspicious path via `Info.IsPrivEscalation()`)
  - Baseline Comparison (new/gone/unchanged)
  - Key Findings (summary table)
- `GenerateJSON(data, filename)` — Writes structured JSON with all scan data, findings summary, DNS lookup count
- `GenerateCSV(data, connFile, riskFile)` — Writes two CSV files: connections and risks
- `IsExternal(c)` — Delegates to `scanner.IsExternalIP()`
- `IsSuspicious(c)` — Returns true if connection target is external (not local/private)
- `IsLocal(addr)` — Delegates to `scanner.IsPrivateIP()`
- `IsSuspiciousProcess(name)` — Checks against `scanner.SuspiciousProcessNamesList()`
- `Summarize(data)` -> `Findings` — Counts: total outbound, external endpoints, suspicious ports, suspicious processes, risk level counts, privilege escalation count (elevated + unsigned via `Info.IsPrivEscalation()`), whitelisted count
- `countFindings()` — Internal helper for `Summarize()`
- `isSuspiciousPort(port)` — Delegates to `scanner.IsSuspiciousPort()`
- `sanitizeMarkdown(s)` — Escapes `|` and `` ` `` for safe Markdown table rendering

**Key types:**
- `Data` — bundles all scan data: System, Connections, Processes, Risks, Security, Baseline, Whitelist
- `Findings` — summary counts (outbound, endpoints, suspicious ports/procs, risk counts, priv esc, whitelisted)
- `WhitelistedIP` — IP + comment for report rendering

**Called by:** `main.go` at step [5/5].

---

### 20. `alerting/alerting.go` — Alert Delivery

**Purpose:** Send alerts to configured notifiers (webhook, syslog/stdout).

**What it does:**
- `Alert` struct — timestamp, level, message, details
- `Notifier` interface — `Name()` + `Send(alert)`
- `WebhookNotifier` — HTTP POST to configured URL with JSON payload
- `SyslogNotifier` — Writes to stderr (cross-platform syslog simulation)
- `Registry` — Manages multiple notifiers, broadcasts alerts to all

**Called by:** `main.go` after risk analysis. If `cfg.Alerting.Enabled` is true, creates a registry, adds webhook notifier (if URL configured) and stdout notifier, then sends alerts for Critical and High risk connections.

---

### 21. `version/version.go` — Version String

**Purpose:** Provides the application version string.

**What it does:**
- `Version` constant — e.g., `"1.0.0"`

**Called by:** `main.go` for banner display and report metadata.

---

### 22. `threatintel/feeds.go` — Live Feed Clients

**Purpose:** HTTP-based fetchers for live threat intelligence from external sources.

**What it does:**
- `ThreatFoxFeedClient` — Fetches from ThreatFox API (`https://threatfox-api.abuse.ch/v1/search`), supports optional API key for higher rate limits
- `FeedCacheManager` — In-memory cache with configurable TTL (default 1h), returns stale cache on fetch errors
- `FeedURLClient` — Fetches from custom JSON feed URLs, auto-tags IOCs with source URL
- `cleanSourceURL()` — Extracts source name from URL for IOC metadata

**Called by:** `main.go` at step [4/5] when `cfg.ThreatIntel.Enabled` is true. Merged into `tiDB` alongside built-in and C2IntelFeeds indicators.

---

### 23. `c2update/` — Standalone C2IntelFeeds Updater

**Purpose:** Independent binary for fetching and updating C2IntelFeeds CSV data. Can be scheduled via cron, systemd timer, or Windows Task Scheduler.

**What it does:**
- `c2update/main.go` — Standalone binary that fetches C2 indicators from the C2IntelFeeds CSV repository and writes them to a JSON feed file
- `c2update/go.mod` — Separate Go module using `replace` directive to pull in `networksentinel/threatintel` types
- Supports flags: `-output`, `-30day`, `-domain`, `-ipport`, `-timeout`
- Deduplicates indicators, wraps in metadata envelope with timestamp and count
- Output format: JSON envelope with `format`, `source`, `generated_at`, `indicator_count`, `indicators`
- Builds to `c2update.exe` (Windows) or `c2update` (Linux)

**Wrapper scripts:**
- `c2update.sh` — Linux/macOS wrapper with logging, cron-compatible
- `c2update.ps1` — Windows PowerShell wrapper, Task Scheduler-compatible
- `c2update.service` / `c2update.timer` — systemd integration (6h interval with 30min jitter)

**Usage:**
```bash
# Manual update
./c2update.sh -output /path/to/c2intel_feeds.json

# Systemd timer
sudo cp c2update.timer c2update.service /etc/systemd/system/
sudo systemctl enable --now c2update.timer

# Scheduled via cron (Linux)
0 */6 * * * /path/to/c2update.sh -output /path/to/c2intel_feeds.json >> /var/log/c2update.log 2>&1

# Scheduled via Task Scheduler (Windows)
schtasks /create /tn "C2IntelFeedsUpdate" /tr "powershell -ExecutionPolicy Bypass -File c2update.ps1" /sc daily /st 02:00
```

**Consumed by:** `networksentinel` via `-feed c2intel_feeds.json` flag, or the `c2intel_feeds.json` can be referenced by `threatintel.GetFeedIOCs()`.

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
|    [1/8] systeminfo.Gather()                                    |
|      -> hostname, OS, local IPs, MAC addresses                   |
|    [2/8] scanner.ScanAll(cfg)                                   |
|      -> enumerateProcesses()  (platform-specific)                |
|      -> getNetConnections()   (platform-specific)                |
|      -> correlate PID -> process name                            |
|      -> determineDirection()                                     |
|      -> filter excluded                                          |
|      -> processinfo.GetProcessInfo(pid) × unique PIDs            |
|         → Returns map[int]processinfo.Info (security context)    |
|    [3/8] DNS: dns.ResolveConnectionsDNS(conns, concurrency)     |
|      -> miekg/dns DNSSession (Google DNS 8.8.8.8:53)           |
|      -> QueryMultiplePTRs() concurrent reverse lookups           |
|      -> Populates c.DNSName on connections                       |
|    [4/8] DNS Capture: dns.CaptureDNSQueries(cfg, hostname)      |
|      -> Platform-specific DNS cache capture                      |
|      -> CheckDomain() for each external connection               |
|      -> Save to JSON file                                        |
|      -> DNSQueriesToIPMap() cross-reference to connections       |
|    [5/8] baseline.Load() + baseline.Diff()                       |
|      -> Key: PID:RemoteAddr:RemotePort                            |
|      -> New / Gone / Unchanged classification                    |
|    [6/8] Threat Intel Aggregation                               |
|      -> Built-in: threatintel.KnownC2IPs (33 indicators)         |
|      -> External file: -feed flag -> GetFeedIOCs()               |
|      -> Live ThreatFox: cfg.ThreatIntel.Enabled -> FeedCacheMgr  |
|      -> C2IntelFeeds CSV: FetchAllIOCs() (~590 indicators)       |
|    [7/8] scanner.AssessConnectionRiskWithThreatIntel()           |
|      -> 6 heuristics per outbound connection                     |
|      -> Threat intel enrichment (confidence boost)               |
|    [8/8] report.GenerateMarkdown() / GenerateJSON() / CSV()     |
|      -> Markdown: full report with all sections                  |
|      -> JSON: structured data with findings summary              |
|      -> CSV: connections + risks spreadsheets                    |
|    alerting.Registry.Send() (if enabled)                         |
|      -> WebhookNotifier (HTTP POST)                              |
|      -> SyslogNotifier (stderr)                                  |
|    baseline.Save()                                               |
|    Print suspicious connections (if any)                         |
|    Print top 10 processes by network activity                    |
+------------------------------------------------------------------+
```

---

## Module Dependencies

```
main.go
  +-- config (Load, DNSConfig, ThreatIntelConfig, Alerting, Thresholds)
  +-- systeminfo (Gather, SystemDetails)
  +-- scanner (ScanAll, AssessConnectionRiskWithThreatIntel, Connection, ProcessEntry, ConnectionRisk, RiskLevel)
  +-- dns (ResolveConnectionsDNS, CaptureDNSQueries, CheckDomain, SaveCaptureResult, DNSQueriesToIPMap, CaptureResult, Query)
  +-- threatintel (NewThreatIntelDB, AddIOCs, GetFeedIOCs, KnownC2IPs, NewThreatFoxFeedClient, NewFeedCacheManager, NewC2IntelFeedsClient, ThreatIntelDB)
  +-- baseline (Load, Diff, Save, DiffResult, Entry)
  +-- report (GenerateMarkdown, GenerateJSON, GenerateCSV, IsSuspicious, IsSuspiciousProcess, Data, WhitelistedIP)
  +-- alerting (NewRegistry, WebhookNotifier, SyslogNotifier, Alert)
  +-- version (Version)

scanner
  +-- config (IsExcludedPID, IsExcludedProcess, IsWhitelistedIP, GetWhitelistComment, Thresholds)
  +-- processinfo (GetProcessInfo, Info, Elevated, SYSTEM, IsSuspiciousPath)
  +-- threatintel (AssessConnectionRiskWithThreatIntel, ThreatIntelDB, LookupConnection)

report
  +-- scanner (IsExternalIP, IsPrivateIP, SuspiciousProcessNamesList, IsSuspiciousPort, Connection, ProcessEntry, ConnectionRisk, RiskLevel, RiskCritical, RiskHigh, RiskMedium, RiskLow)
  +-- baseline (DiffResult, Entry)
  +-- processinfo (Info, Elevated, SYSTEM)
  +-- systeminfo (SystemDetails)
  +-- dns (CaptureResult)
  +-- version (Version)

dns/lookup
  +-- scanner (Connection) — ResolveConnectionsDNS imports scanner.Connection

dns/query_windows, query_linux, query_darwin
  +-- config (Config, DNSLog)

processinfo
  +-- (no internal dependencies)

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

c2update (standalone binary)
  +-- (no internal dependencies — self-contained fetch + JSON output)

ui/main.go (Wails GUI)
  +-- baseline (Load, Diff, Save, Entry, DiffResult)
  +-- config (Load, Config, Defaults, Thresholds, DNSConfig, Alerting, ThreatIntelConfig, WhitelistedIP, Excluded)
  +-- dns (CaptureDNSQueries, DNSQueriesToIPMap, CaptureResult, Query)
  +-- processinfo (Info, Elevated, SYSTEM)
  +-- report (Data, Summarize, Findings)
  +-- scanner (ScanAll, AssessConnectionRiskWithThreatIntel, Connection, ProcessEntry, ConnectionRisk)
  +-- systeminfo (Gather)
  +-- threatintel (NewThreatIntelDB, AddIOCs, KnownC2IPs, NewThreatFoxFeedClient, NewFeedCacheManager, NewC2IntelFeedsClient)
  +-- ui/configmgr (ConfigManager, NewConfigManager, Snapshot)

ui/configmgr
  +-- config (Config)
```

### Dependency Graph Summary

```
main.go ──imports──► config, systeminfo, scanner, dns, threatintel, baseline, report, alerting, version
scanner ──imports──► config, processinfo, threatintel
report ──imports──► scanner, baseline, processinfo, systeminfo, dns, version
dns/lookup ──imports──► scanner (Connection type only)
dns/query_* ──imports──► config
ui/main ──imports──► baseline, config, dns, processinfo, report, scanner, systeminfo, threatintel, ui/configmgr
ui/configmgr ──imports──► config
c2update ──imports──► (none — standalone)

All other packages ──imports──► (none — leaf modules)

No circular dependencies. All dependencies flow inward toward leaf modules.
```

---

## Key Design Patterns

1. **Platform abstraction via build tags** — Each OS has its own implementation file (`_windows.go`, `_linux.go`, `_darwin.go`). The shared code in `scanner.go` and `processinfo.go` compiles across all platforms.

2. **Dependency injection** — `config.Config` is passed throughout the pipeline, allowing all modules to access thresholds, exclusions, whitelist, DNS config, and threat intel settings without global state.

3. **Chain of heuristics** — `AssessConnectionRisk()` applies 6 independent checks, then aggregates reasons to determine risk level. Each heuristic is a pure function that can be tested independently. Uses on-stack `[6]string` array for zero-alloc reasons.

4. **Data bundling** — `report.Data` aggregates all scan results into a single struct, making it easy to pass to report generators without complex parameter lists.

5. **Interface-based alerting** — `Notifier` interface allows adding new alert delivery mechanisms (Slack, PagerDuty, etc.) without modifying existing code.

6. **Parallel worker pools** — `dns.QueryMultiplePTRs()` uses miekg/dns concurrent reverse lookups. Each lookup has timeout control. Deduplication avoids redundant work.

7. **Cached feed clients** — `FeedCacheManager` provides TTL-based caching for live threat intel feeds. Returns stale cache on fetch failure, preventing scan failure from network issues.

8. **Standalone updater** — `c2update/` is a separate Go module with its own `go.mod`, built independently from `networksentinel`. Consumed via `-feed` flag. Enables scheduled updates without modifying the main binary.

9. **Generic CSV parser with config struct** — `parseCSVFeed()` in `c2intelfeeds.go` uses a `csvFeedConfig` struct to parameterize column count, header skip, confidence, tags, source, and port column. Three feed types (IP, IP+port, domain) each delegate to the same parser with different configs, eliminating ~90 lines of duplicated parsing logic.

10. **Platform-specific pattern injection via init()** — `suspiciousPathPatterns` is a shared global slice populated by each OS-specific `init()` function. `IsSuspiciousPath()` in the shared `processinfo.go` iterates over the slice. This provides platform-aware detection without code duplication while keeping a single shared implementation.

11. **Unified privilege escalation detection** — `Info.IsPrivEscalation()` method in `processinfo.go` is the single source of truth for scanner and report. Eliminates the previous duplication where the report used crude `strings.Contains(..., "temp")` substring checks that produced false positives (e.g., `C:\temporal\program.exe`).

12. **miekg/dns DNS session** — `DNSSession` wraps miekg/dns client with Google DNS 8.8.8.8:53. Provides `QueryDomain()`, `QueryDomainPTR()`, `QueryMultipleDomains()`, `QueryMultiplePTRs()` methods. Replaced unreliable `net.Resolver` reverse DNS on Windows.

13. **Three-tier DNS capture** — Platform-specific native tools first (PowerShell `Get-DnsClientCache`, `journalctl`, `dscacheutil`), then log files (`/var/log/syslog`, macOS `log show`), then miekg/dns PTR fallback. `CaptureMethod` string tracks which method succeeded.

14. **Wails GUI integration** — `ui/main.go` wraps the entire scanning pipeline into a Wails desktop app. Mirrors `main.go`'s `runScan()` in `App.RunScan()`, returns structured JSON responses for React frontend. Embeds frontend assets via `//go:embed all:frontend/dist`.

15. **Config snapshot management** — `ui/configmgr` provides named snapshots, export, and save operations. Enables config versioning without modifying core config package.
