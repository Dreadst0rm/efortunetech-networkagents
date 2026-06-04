# NetworkSentinel — Windows 使用指南

## 概述

NetworkSentinel 是一个 Go 编写的网络安全分析工具，用于扫描本机网络连接、关联进程、执行多启发式风险评估，并生成报告。

**版本**: 0.4.0
**许可证**: Apache 2.0
**运行平台**: Windows 10/11, Windows Server 2016+ (x64)

---

## 快速开始

### 1. 运行扫描

```powershell
.\networksentinel.exe
```

这将执行一次完整扫描，输出结果到控制台，并生成以下文件：

```
network_sentinel_<主机名>_<时间戳>.md   — Markdown 报告
network_sentinel_<主机名>_<时间戳>.json — JSON 报告
network_sentinel_<主机名>_<时间戳>_connections.csv  — 连接数据
network_sentinel_<主机名>_<时间戳>_risks.csv        — 风险评估
baseline.json                                           — 基线快照
```

### 2. 查看报告

打开生成的 Markdown 报告，它包含：

- **系统信息** — 主机名、操作系统、本地 IP
- **网络连接摘要** — 总连接数、出站/入站/内部连接数、TCP 状态分布
- **外部端点** — 远程地址和端口列表
- **可疑连接** — 被标记的连接
- **风险评估摘要** — Critical / High / Medium / Low 数量
- **按网络活动排序的进程** — Top 20 进程
- **特权升级分析** — 检测到的特权升级链
- **基线对比** — 新增/消失/未变的连接

---

## 命令行参数

```
Usage of networksentinel.exe:
  -config string
        配置文件路径 (默认 "config.json")
  -daemon int
        守护进程模式扫描间隔（秒），0 = 单次模式
  -h    显示帮助
  -output string
        报告输出目录 (默认 ".")
```

### 示例

**单次扫描（默认）：**
```powershell
.\networksentinel.exe
```

**指定配置文件：**
```powershell
.\networksentinel.exe -config C:\tools\sentinel_config.json
```

**指定输出目录：**
```powershell
.\networksentinel.exe -output C:\reports
```

**守护进程模式（每 60 秒扫描一次）：**
```powershell
.\networksentinel.exe -daemon 60
```

按 `Ctrl+C` 停止守护进程。

---

## 配置文件

### 位置

默认 `config.json`，与 `networksentinel.exe` 在同一目录。

### 结构

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

### 参数说明

#### thresholds（阈值）

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `min_ip_connections` | int | 5 | 同一远程 IP 的出站连接数达到此值时触发告警 |
| `min_process_connections` | int | 5 | 同一进程的出站连接数达到此值时触发告警 |
| `critical_threshold` | int | 3 | 需要多少条启发式原因才能标记为 Critical |
| `high_threshold` | int | 2 | 需要多少条启发式原因才能标记为 High |

#### excluded（排除项）

跳过特定 PID 或进程名的扫描。常用于排除已知安全的系统进程。

```json
"excluded": {
  "pids": [4, 444, 1284],
  "processes": ["MsMpEng.exe", "AntimalwareServiceHost.exe"]
}
```

#### dns_log（DNS 日志）

启用后，NetworkSentinel 会通过 PowerShell WMI 查询 DNS 客户端缓存，并对域名进行可疑性评分。

```json
"dns_log": true
```

**Windows DNS 采集方式：** `Get-CimInstance MSFT_DNSClientCache`

**域名可疑性评分因素：**

| 因素 | 评分 |
|------|------|
| 可疑 TLD（.xyz, .tk, .ml, .ga, .cf, .ru, .cn 等） | 0.4 - 0.7 |
| 高子域名深度（>= 4 个点） | +0.3 |
| 可疑关键词（login, account, secure, verify, admin, banking, crypto 等） | +0.2 |
| 域名过长（> 50 字符） | +0.4 |
| 高辅音比例（> 5:1） | +0.3 |

评分 >= 0.6 标记为可疑。

#### alerting（告警）

启用后，Critical 和 High 风险连接会通过 Webhook 和标准错误输出告警。

```json
"alerting": {
  "enabled": true,
  "webhook_url": "https://your-webhook.example.com/alerts"
}
```

**告警输出格式（stderr）：**
```
[2026-06-03 14:30:00] [CRITICAL] stdout: chrome.exe (PID: 3076) -> 173.194.64.188:5228
```

**告警 JSON payload（Webhook POST）：**
```json
{
  "timestamp": "2026-06-03T14:30:00.1234567-05:00",
  "level": "critical",
  "message": "chrome.exe (PID: 3076) -> 173.194.64.188:5228",
  "details": "suspicious port 5228; high connection count to 173.194.64.188 (7)"
}
```

---

## 风险评估

### 6 大启发式规则

所有规则仅针对 **出站（outbound）** 连接进行评估。

#### 1. 可疑端口检测

检查远程端口是否匹配已知 C2/代理端口：

| 端口 | 常见用途 |
|------|----------|
| 4444 | Metasploit 默认 |
| 5555 | Android Debug Bridge |
| 6666-6669 | IRC / C2 |
| 7777 | 常见后门 |
| 8888 / 9999 | 代理 / 开发服务器 |
| 1080 / 1081 | SOCKS 代理 |
| 3128 | Squid 代理 |
| 8080 / 8443 | 代理 / 替代 HTTPS |
| 1337 | 常见 C2 |
| 9001 / 9050 / 9051 | Tor |
| 2525 / 4242-4244 | 各种 C2 |
| 1234 | 常见后门 |

#### 2. 可疑进程名

检查进程是否在 Windows 可疑进程列表中：

```
cmd.exe, powershell.exe, wscript.exe, cscript.exe, wmic.exe,
certutil.exe, bitsadmin.exe, dns.exe, net.exe, ssh.exe,
curl.exe, netsh.exe, sc.exe, whoami.exe, mshta.exe,
regsvr32.exe, msbuild.exe, tasklist.exe, ipconfig.exe
```

#### 3. 异常 TCP 状态

检测以下 TCP 状态（可能指示扫描或隐蔽通道）：

- `SYN_SENT` — 连接正在建立
- `SYN_RECEIVED` — 连接等待完成
- `TIME_WAIT` — 连接正在关闭
- `CLOSE_WAIT` — 远程端已关闭连接

#### 4. 高 IP 连接数

同一远程 IP 的出站连接数超过 `min_ip_connections` 阈值。

#### 5. 高进程连接数

同一进程的出站连接数超过 `min_process_connections` 阈值。

#### 6. 特权升级链检测

检测以下危险组合：

| 组合 | 说明 |
|------|------|
| 提升 + 未签名 + 临时路径 | 最高风险 |
| 提升 + 未签名 | 中等风险 |
| 提升 + 临时路径 | 中等风险 |

**检测内容：**
- **特权级别** — 通过 PowerShell 查询令牌提升状态
- **代码签名** — 通过 Authenticode 验证
- **执行路径** — 检查是否位于 temp/tmp/AppData\Local\Temp
- **完整性级别** — Low / Medium / High / System

### 风险等级

| 等级 | 条件 |
|------|------|
| **Critical** | >= `critical_threshold` 条启发式原因（默认 3） |
| **High** | >= `high_threshold` 条启发式原因（默认 2） |
| **Medium** | 恰好 1 条启发式原因 |
| **Low** | 0 条原因（不输出） |

---

## 威胁情报源

NetworkSentinel 内置了对已知 C2（命令与控制）基础设施的威胁情报匹配功能。当连接或 DNS 查询匹配已知指标时，风险评估会提升并包含详细的威胁情报上下文。

### 内置数据源

工具内置 **33 个指标**（22 个 IP 地址，11 个域名），涵盖：

| 类别 | 数量 | 示例 |
|------|------|------|
| C2 框架 | 10 | CobaltStrike, Metasploit, Empire, Sliver, BruteRatel, Covenant, Mythic, Deimos, Havoc, Caldera |
| 恶意软件家族 | 9 | LummaStealer, MeduzaStealer, QuasarRAT, DarkComet, njRAT, RemcosRAT, PoisonIvy, AsyncRAT, ShadowPad |
| 钓鱼域名 | 11 | secure-login-verify.tk, account-verify-secure.xyz, portal-auth-verify.top 等 |

每个指标包含：恶意软件家族名称、首次/最后出现日期、国家代码、置信度评分（0-100）、标签、来源数据源和状态。

### 工作原理

在风险评估期间，每个出站连接的远程地址会与 C2 数据库进行交叉检查。DNS 查询也会被交叉引用。当匹配到已知指标时：

- **置信度 >= 90** → 风险等级提升至 **Critical**
- **置信度 >= 80** → 风险等级提升至 **High**（如果尚未更高）
- 添加 `THREAT_INTEL` 原因，包含恶意软件家族、来源、置信度、国家和标签

报告示例：
```
THREAT_INTEL: CobaltStrike (threatfox) confidence=95 country=RU tags=[c2, cobalt-strike, rat]
```

### 更新数据源

内置数据源是来自开源威胁情报（ThreatFox、C2-Tracker、Spamhaus Xanadu）的代表性子集。要使用最新指标进行更新：

1. **下载新数据源** — 选择来源（见下文）
2. **将指标添加到代码中** — 编辑 `threatintel/feeds.go` 并向 `KnownC2IPs` 追加新的 `IOC` 结构体
3. **重新编译** — `go build -o networksentinel.exe .`

**推荐的数据源：**

| 来源 | 格式 | 覆盖内容 |
|------|------|----------|
| ThreatFox (abuse.ch) | JSON API | Cobalt Strike、Metasploit、Empire、Sliver 等 50+ 框架的 C2 IP 和域名 |
| C2-Tracker (montysecurity) | 纯文本 | 来自 Shodan/Censys 的社区维护 C2 基础设施 |
| Spamhaus Xanadu | 纯文本 | 高信誉 C2 IP 黑名单 |
| AbuseIPDB | JSON/纯文本 | 带置信度评分的广泛 IP 滥用情报 |
| PhishStats | JSON | 钓鱼基础设施和 URL |

**示例：从 ThreatFox 添加**

```powershell
# 下载 ThreatFox 数据源
curl -s https://threatfox.abuse.ch/export/tcp/json/ | python3 -c "
import json, sys
data = json.load(sys.stdin)
for ioc in data['iocs'][:50]:  # 前 50 个
    print(f'{ioc[\"ip\"]} {ioc[\"malware\"]} {ioc[\"country\"]} {ioc[\"port\"]}')
"
```

然后添加到 `threatintel/feeds.go`：

```go
var KnownC2IPs = []IOC{
    // ... 现有指标 ...
    {Indicator: "185.141.22.206", IndicatorType: "ipv4", MalwareFamily: "NewC2Framework", FirstSeen: time.Now(), LastSeen: time.Now(), Country: "US", Confidence: 90, Tags: []string{"c2", "new-framework"}, Source: "threatfox", Status: "active", Port: 443},
}
```

**使用脚本自动化更新**

在项目目录中创建 `update-feeds.sh`：

```bash
#!/bin/bash
# 下载并准备 ThreatFox 指标供手动添加
curl -s https://threatfox.abuse.ch/api/v1/browse/ | \
    python3 -c "
import json, sys, re
data = json.load(sys.stdin)
seen = set()
for ioc in data.get('iocs', [])[:100]:
    ip = ioc.get('ip', '')
    malware = ioc.get('malware', 'Unknown')
    country = ioc.get('country', '??')
    if ip and ip not in seen:
        seen.add(ip)
        print(f'# ThreatFox: {ip} ({malware}, {country})')
" > threatfox_indicators.txt

echo "查看 threatfox_indicators.txt 并将新的 IOC 结构体添加到 threatintel/feeds.go"
```

**更新频率建议：** 生产环境中每周更新威胁情报源，或连续监控时每日更新。

---

## 基线对比

每次扫描后，NetworkSentinel 会自动保存当前连接快照到 `baseline.json`。下次运行时，会将当前连接与基线对比：

- **New** — 新增连接
- **Gone** — 消失的连接
- **Unchanged** — 未变的连接

首次运行时没有基线，会创建一个新的。

---

## 守护进程模式

```powershell
.\networksentinel.exe -daemon 60
```

- 每 60 秒执行一次完整扫描
- 每次扫描都会保存新的基线
- 每次扫描都会生成带时间戳的报告文件
- 按 `Ctrl+C` 优雅退出

---

## 输出文件详解

### Markdown 报告

```markdown
# Network Sentinel Report
Hostname: Goliath
OS: windows
Scan Time: 2026-06-03 14:30:00

## Network Connections Summary
Total Connections: 156
Outbound: 89
Inbound: 45
Internal: 22

## Risk Analysis Summary
Critical: 2
High: 5
Medium: 12
Low: 3

## Privilege Escalation Analysis
PID    | Process      | Privilege | Signed | Path
3001   | malware.exe  | elevated  | No     | C:\Users\User1\AppData\Local\Temp\malware.exe
```

### JSON 报告

```json
{
  "version": "0.4.0",
  "scan_time": "2026-06-03T14:30:00.1234567-05:00",
  "system": {
    "hostname": "Goliath",
    "os_platform": "windows",
    "local_ips": ["192.168.1.100", "10.0.0.50"]
  },
  "connections": [...],
  "processes": [...],
  "risks": [...],
  "security": {
    "1234": {
      "PID": 1234,
      "Name": "chrome.exe",
      "Username": "User1",
      "ExePath": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
      "PrivLevel": "standard",
      "IsSystem": false,
      "Integrity": "medium",
      "Signer": "Google LLC",
      "IsSigned": true,
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
    "TotalOutbound": 89,
    "ExternalEndpoints": 45,
    "SuspiciousPorts": 3,
    "SuspiciousProcesses": 2,
    "PrivEscalationCount": 1
  }
}
```

### CSV 文件

**connections.csv** 列：
```
ProcessID,Process,Executable,LocalAddr,LocalPort,RemoteAddr,RemotePort,Protocol,State,Direction
```

**risks.csv** 列：
```
RiskLevel,ProcessID,Process,LocalAddr,LocalPort,RemoteAddr,RemotePort,State,Direction,Reasons
```

---

## 权限要求

NetworkSentinel 需要以**标准用户权限**运行即可收集所有信息。部分功能（如代码签名验证、令牌提升检测）需要进程具有读取权限，但不会要求管理员权限。

**推荐的运行方式：**

```powershell
# 标准用户运行
.\networksentinel.exe

# 管理员运行（获取更完整的进程信息）
Start-Process -Verb RunAs -FilePath ".\networksentinel.exe"
```

---

## 故障排除

### 扫描失败 — "wmic process failed"

某些 Windows 版本已弃用 `wmic`。确保系统支持 wmic 命令：

```powershell
wmic process get Name,ProcessId /format:list
```

如果失败，说明系统可能已禁用 wmic。

### DNS 采集返回空

`MSFT_DNSClientCache` WMI 类可能不存在于某些 Windows 版本。DNS 采集失败不会影响其他功能。

### 报告未生成

检查输出目录是否存在：

```powershell
.\networksentinel.exe -output C:\reports
# 确保 C:\reports 目录存在
```

### 配置加载失败

配置文件必须是有效 JSON：

```powershell
# 验证 JSON 格式
Get-Content config.json | ConvertFrom-Json
```

---

## 性能

- **单次扫描时间**：约 5-15 秒（取决于进程/连接数量）
- **内存占用**：约 20-50 MB
- **守护进程模式**：每次扫描独立执行，不会累积内存

---

## 安全注意事项

1. **本工具仅用于授权的安全测试和监控**
2. **不要在生产环境无授权的情况下运行**
3. **基线文件 `baseline.json` 包含网络连接数据，应妥善保护**
4. **告警 Webhook URL 不应硬编码在配置中，建议使用环境变量**
5. **守护进程模式会在后台持续运行，确保系统安全监控策略允许**

---

## 更新日志

### v0.4.0
- 新增 CLI 参数（-config, -output, -daemon, -h）
- 新增守护进程模式
- 新增 DNS 日志和可疑域名检测
- 新增 Webhook 和标准错误告警
- 新增特权升级链检测
- 新增代码签名验证
- 新增基线对比功能
- 新增 Markdown / JSON / CSV 多格式报告
- 全平台支持（Windows / Linux / macOS）
