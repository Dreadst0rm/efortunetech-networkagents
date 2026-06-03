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
