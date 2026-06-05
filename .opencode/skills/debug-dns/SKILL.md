---
name: debug-dns
description: Diagnose DNS capture failures and DNS name resolution gaps in reports
license: MIT
compatibility: opencode
metadata:
  stage: build
---

# Debug DNS

## When to use
- "DNS not showing in report" / "DNS results missing" / "DNS names empty"
- "DNS capture failed" / "DNS queries not captured"
- Any issue where DNS names appear blank in reports or logs

## Workflow

1. **Check `cfg.DNSLog`** — Is `dns_log: true` in config.json? If not, DNS capture is disabled.
2. **Check `captureResult.CaptureMethod`** — What method was used? Look for `_failed` suffix.
3. **Check `captureResult.Queries`** — Is it nil or empty? If so, capture failed.
4. **Check platform-specific DNS capture mechanism**:
   - **Windows**: `Get-DnsClientCache` PowerShell cmdlet (NOT `MSFT_DNSClientCache` WMI class — removed in Windows 10/11)
   - **Linux**: `journalctl -u systemd-resolved` or `/var/log/syslog`
   - **macOS**: `dscacheutil` or `log show`
5. **Check `DNSQueriesToIPMap`** — Does it build a map from the captured queries?
6. **Check cross-reference loop** — Does `main.go` call `DNSQueriesToIPMap()` and populate `c.DNSName`?
7. **Check report code** — Does the report use `extDNS[addr]` instead of hardcoded `""`?

## Guardrails
- **Never assume DNS capture worked** — always check `CaptureMethod` and `Queries` length
- **Windows DNS cache**: Use `Get-DnsClientCache`, NOT `Get-CimInstance -ClassName MSFT_DNSClientCache` (removed in Win10/11)
- **DNS names in reports**: The report needs two fixes — (1) capture must work, (2) report must use captured DNS names instead of empty string
- **Don't fix symptoms first** — check if capture is even running before debugging cross-reference logic
