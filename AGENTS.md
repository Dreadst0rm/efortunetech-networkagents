# efortunetech-networkagents

## Project Rules
- **Never mix debug and refactor in the same step** → Always isolate changes
- **Phase-by-phase development** → Complete one phase before starting the next
- **Windows-only dependencies** → No CGo for Windows-specific features, use PowerShell or native APIs via syscall
- **Build after every code change** → Verify with `go build -o networksentinel.exe .`
- **Run after every build** → Verify output with `.\networksentinel.exe`
- **No global state or unexported dependencies** → Use typed constants and explicit interface contracts

## Architecture Patterns
- **Cross-platform scanning**: scanner/scanner.go contains shared types + risk scoring; platform-specific IO in _windows/_linux/_darwin files via `//go:build` tags
  - Windows: wmic + netstat
  - Linux: /proc/PID/comm + /proc/net/tcp{,6} inode → PID mapping
  - Darwin: ps axco pid,comm + lsof -nP -i with STATE field parsing
- **Cross-platform processinfo**: Scanner.go uses `scanner.SuspiciousProcessNamesList()` for platform-aware suspicious names; types-only in shared processinfo.go; per-OS impls via build tags
- **processinfo_processSecurityInfo** carries per-PID security context (priv elevation, signing, PATH); Windows uses powershell + WinToken P/Invoke + signtool; Linux uses /proc/PID/status + /etc/passwd; Darwin uses lsof + ID
- **Scanner**: Multi-heuristic (port + process + connection count + state), not single-factor
- **Report separation**: Markdown generation is independent of data collection, uses scanner.SuspiciousProcessNamesList() for platform consistency

## Known Issues
- Windows `wmic` output has variable blank line spacing (1 between fields, 3+ between entries)
- netstat parsing must handle IPv6 bracket notation `[::]:*` vs IPv4 `0.0.0.0:*`
- Go `exec.Command` output is Windows ANSI-encoded by default

## Phase 3 - COMPLETE: Privilege escalation chain detection

Completed features:
- [x] Privilege escalation chain detection (admin + unsigned + temp path)
- [x] Code signing verification
- [x] Process integrity level via Windows API
- [x] User context detection (SYSTEM vs user)
- [x] Full integration of `processinfo` into `scanner.ScanAll()` and `AssessConnectionRisk()`
- [x] Privilege escalation section in markdown report with per-PID table
- [x] Cross-platform `processinfo` (Windows/Linux/Darwin) wired end-to-end

Key implementation:
- Uses `powershell.exe` via `exec.Command` (no CGo per AGENTS.md rule)
- Checks token elevation, integrity level, code signing, execution path
- Detects admin-level + unsigned + temp path → escalation chain
- `processinfo.Info` structure per PID, returned as `map[int]processinfo.Info` from `ScanAll()`
- `AssessConnectionRisk()` accepts `secInfo` map, adds heuristic #6 (privilege escalation chain)
- Report includes "Privilege Escalation Analysis" section + `PrivEscalationCount` in findings
- Cross-compilation verified for all three targets (Windows/Linux/Darwin)

## Lessons Learned
- **wmic output parsing**: Fields separated by 1 blank line, but entries by 3+ consecutive blank lines. Use emit-on-both-fields strategy, not blank-counting.
- **PowerShell command chaining**: Use `;` and `$?` for conditional chaining in PowerShell 5.1, not `&&`. Correct pattern: `cmd1; if ($?) { cmd2 }`
- **IPv6 bracket handling**: Windows IPv6 uses `[::1]:port` format with brackets. Strip brackets (`[`, `]`) before IP prefix matching, always
- **Go strings.Builder double-paren**: Easy to accidentally add extra `)` in sb.WriteString() calls. Always verify after editing.
- **Build verification**: Always run `go build` after any code change before proceeding to avoid cascading errors.
- **No CGo on Windows**: For Windows-specific features (token/elevation checks), use PowerShell via `exec.Command` or syscall — never CGo/CGO_ENABLED=1
- **Slice modification in range loops**: `for _, c := range conns` copies values. Use `for i := range conns { c := &conns[i] }` to modify slice elements.
- **DNS timeout**: Always wrap `net.LookupAddr` or `net.Resolver` calls with `context.WithTimeout(2s)` — never use raw DNS calls without timeout. `net.Resolver` does not have a `Timeout` field.
- **Config validation**: Validate all user-provided config values at load time. Use `net.ParseIP()` to reject invalid IPs in whitelist entries. Clear invalid entries, don't crash.
- **Markdown table sanitization**: Escape `|` and `` ` `` characters in user-provided strings before writing to Markdown tables. Use `strings.ReplaceAll(s, "|", "\\|")` and `strings.ReplaceAll(s, "`", "\\`")`.
- **go.mod version**: Match your toolchain. Use `go 1.26` (not `1.26.2` — patch versions don't go in go.mod).
- **Cover story for HighestRisk**: `scanner.RiskLevel` is a string type. String comparison `"critical" > "medium"` is false alphabetically. The `>` comparison in `AssessConnectionRisk` picks the first risk as highest — existing code, not a new bug.
- **Security review checklist**: When reviewing new code, check: (1) secrets/credentials, (2) shell injection in exec.Command, (3) input validation, (4) output encoding, (5) dependency CVEs, (6) file path safety.
- **Karpathy guidelines**: Think before coding (surface tradeoffs), simplicity first (200 lines → 50), surgical changes (touch only what's requested), goal-driven execution (verifiable success criteria).
- **PowerShell output**: Use `Select-Object -First N` instead of `| head`. Use `Get-ChildItem` with `Where-Object` for filtering. Use `ForEach-Object` for iteration.
- **Go test coverage**: Use `go test ./... -coverprofile=c.out` then `go tool cover -func c.out` for per-function coverage detail. All packages must pass before proceeding.
