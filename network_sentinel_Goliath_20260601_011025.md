# Process Network Analysis Report

**Scan time:** Mon, 01 Jun 2026 01:10:25 CDT

## System Information

| Field | Value |
|-------|-----|
| Hostname | `Goliath` |
| OS | `windows` |
| Local IPs | `192.168.0.90, 172.25.32.1, 172.27.208.1` |

## Network Connections Summary

| Metric | Count |
|--------|--+--|
| Total connections | 103 |
| Outbound | 20 |
| Inbound | 83 |
| Connection states | CLOSE_WAIT=9; ESTABLISHED=47; FIN_WAIT_2=1; LISTENING=46 |

## External Endpoints

| Remote Address | Ports |
|------|----|
| `104.18.125.108` | `443` |
| `173.194.64.188` | `443` |
| `199.232.197.91` | `443` |
| `199.232.210.172` | `80` |
| `2.21.9.196` | `443` |
| `20.189.173.18` | `443` |
| `23.54.78.147` | `443` |
| `3.223.97.185` | `443` |
| `34.196.216.236` | `443` |
| `50.19.128.171` | `443` |
| `52.110.7.26` | `443` |
| `52.110.7.39` | `443` |
| `52.96.191.226` | `443` |
| `52.96.79.50` | `443` |
| `54.174.170.30` | `443` |

## Suspicious Connections

| Process | PID | Remote Address | Port | State |
|---------|---|-+------|--+---|---+---|
| `EpicGamesLauncher.exe` | 33320 | `50.19.128.171` | 443 | `ESTABLISHED` |
| `chrome.exe` | 23960 | `173.194.64.188` | 443 | `ESTABLISHED` |
| `nvcontainer.exe` | 14716 | `23.54.78.147` | 443 | `CLOSE_WAIT` |
| `nvcontainer.exe` | 14716 | `23.54.78.147` | 443 | `CLOSE_WAIT` |
| `nvcontainer.exe` | 14716 | `23.54.78.147` | 443 | `CLOSE_WAIT` |
| `nvcontainer.exe` | 14716 | `23.54.78.147` | 443 | `CLOSE_WAIT` |
| `nvcontainer.exe` | 14716 | `23.54.78.147` | 443 | `CLOSE_WAIT` |
| `explorer.exe` | 13496 | `52.110.7.26` | 443 | `ESTABLISHED` |
| `explorer.exe` | 13496 | `52.96.79.50` | 443 | `ESTABLISHED` |
| `svchost.exe` | 3668 | `199.232.210.172` | 80 | `ESTABLISHED` |
| `nvcontainer.exe` | 14716 | `2.21.9.196` | 443 | `CLOSE_WAIT` |
| `OneDrive.Sync.Service.exe` | 20076 | `20.189.173.18` | 443 | `ESTABLISHED` |
| `EpicGamesLauncher.exe` | 33320 | `54.174.170.30` | 443 | `CLOSE_WAIT` |
| `EpicGamesLauncher.exe` | 33320 | `3.223.97.185` | 443 | `CLOSE_WAIT` |
| `EpicWebHelper.exe` | 25008 | `104.18.125.108` | 443 | `ESTABLISHED` |
| `EpicWebHelper.exe` | 25008 | `34.196.216.236` | 443 | `ESTABLISHED` |
| `explorer.exe` | 13496 | `52.96.191.226` | 443 | `ESTABLISHED` |
| `explorer.exe` | 13496 | `52.110.7.39` | 443 | `ESTABLISHED` |
| `msedge.exe` | 24492 | `199.232.197.91` | 443 | `ESTABLISHED` |

## Risk Analysis Summary

| Risk Level | Count |
|-----------|------|
| **CRITICAL** | 5 |
| **HIGH** | 1 |
| **MEDIUM** | 2 |
| **LOW** | 0 |
| **TOTAL** | 20 |

## Top Processes by Network Activity

| Process | PID | Connections |
|---------|---|-----------|
| `nvcontainer.exe` | 14716 | 18 |
| `System` | 4 | 17 |
| `svchost.exe` | 3332 | 11 |
| `ollama.exe` | 6552 | 6 |
| `OpenCode.exe` | 19136 | 6 |
| `Razer Synapse Service Process.exe` | 19392 | 5 |
| `EpicGamesLauncher.exe` | 33320 | 4 |
| `explorer.exe` | 13496 | 4 |
| `chrome.exe` | 23960 | 3 |
| `msedge.exe` | 24492 | 3 |
| `EpicWebHelper.exe` | 25008 | 2 |
| `OneDrive.Sync.Service.exe` | 20076 | 2 |
| `RzSDKServer.exe` | 6004 | 2 |
| `wininit.exe` | 1072 | 2 |
| `spoolsv.exe` | 4980 | 2 |
| `lsass.exe` | 1180 | 2 |
| `vmms.exe` | 2968 | 2 |
| `services.exe` | 1152 | 2 |
| `MSI.CentralServer.exe` | 10360 | 2 |
| `OneDrive.exe` | 5508 | 1 |

## Key Findings

| Finding | Count |
|---------|------|
| Outbound connections | 20 |
| External endpoints | 15 |
| Suspicious ports | 0 |
| Suspicious processes | 0 |
| Critical risk connections | 5 |
| High risk connections | 1 |
| Medium risk connections | 2 |
| Low risk connections | 0 |
