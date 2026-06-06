package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	"networksentinel/baseline"
	"networksentinel/config"
	"networksentinel/dns"
	"networksentinel/processinfo"
	"networksentinel/report"
	"networksentinel/scanner"
	"networksentinel/systeminfo"
	"networksentinel/threatintel"
	"networksentinelui/configmgr"
)

//go:embed all:frontend/dist
var assets embed.FS

// App struct
type App struct {
	ctx            context.Context
	configMgr      *configmgr.ConfigManager
	configPath     string
	config         *config.Config
	lastScan       *ScanResult
	lastReport     string
	lastBaseline   string
	outputDir      string
}

// ScanResult holds the output of a scan.
type ScanResult struct {
	System      *SystemInfoResp   `json:"system"`
	Connections []ConnectionResp  `json:"connections"`
	Processes   []ProcessResp     `json:"processes"`
	Risks       []RiskResp        `json:"risks"`
	Security    []SecurityResp    `json:"security"`
	Baseline    *BaselineResp     `json:"baseline"`
	Findings    *FindingsResp     `json:"findings"`
	DNSQueries  *DNSQueriesResp   `json:"dns_queries"`
	ScanTime    string            `json:"scan_time"`
	DNSLookups  int               `json:"dns_lookups"`
}

type SystemInfoResp struct {
	Hostname     string   `json:"hostname"`
	OSPlatform   string   `json:"os_platform"`
	LocalIPs     []string `json:"local_ips"`
}

type ConnectionResp struct {
	ProcessID  int    `json:"process_id"`
	Process    string `json:"process"`
	Executable string `json:"executable"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	Direction  string `json:"direction"`
	DNSName    string `json:"dns_name"`
}

type ProcessResp struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

type RiskResp struct {
	ProcessID     int      `json:"process_id"`
	Process       string   `json:"process"`
	Executable    string   `json:"executable"`
	LocalAddr     string   `json:"local_addr"`
	LocalPort     int      `json:"local_port"`
	RemoteAddr    string   `json:"remote_addr"`
	RemotePort    int      `json:"remote_port"`
	Protocol      string   `json:"protocol"`
	State         string   `json:"state"`
	Direction     string   `json:"direction"`
	DNSName       string   `json:"dns_name"`
	RiskLevel     string   `json:"risk_level"`
	RiskReasons   []string `json:"risk_reasons"`
	IsSuspicious  bool     `json:"is_suspicious"`
	IsWhitelisted bool     `json:"is_whitelisted"`
}

type SecurityResp struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	ExePath    string `json:"exe_path"`
	PrivLevel  string `json:"priv_level"`
	IsSigned   bool   `json:"is_signed"`
	IsElevated bool   `json:"is_elevated"`
	Username   string `json:"username"`
}

type BaselineResp struct {
	New         []BaseEntryResp `json:"new"`
	Gone        []BaseEntryResp `json:"gone"`
	Unchanged   int             `json:"unchanged"`
	BaselineAge string          `json:"baseline_age"`
}

type BaseEntryResp struct {
	ProcessID  int    `json:"pid"`
	Process    string `json:"process"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
}

type FindingsResp struct {
	TotalOutbound       int    `json:"total_outbound"`
	ExternalEndpoints   int    `json:"external_endpoints"`
	SuspiciousPorts     int    `json:"suspicious_ports"`
	SuspiciousProcs     int    `json:"suspicious_procs"`
	HighestRisk         string `json:"highest_risk"`
	CriticalCount       int    `json:"critical_count"`
	HighCount           int    `json:"high_count"`
	MediumCount         int    `json:"medium_count"`
	LowCount            int    `json:"low_count"`
	PrivEscalationCount int    `json:"priv_esc_count"`
	WhitelistedCount    int    `json:"whitelisted_count"`
}

type DNSQueriesResp struct {
	Queries []DNSQDetail `json:"queries"`
	Method  string       `json:"method"`
}

type DNSQDetail struct {
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	QueryName string `json:"query_name"`
	Timestamp string `json:"timestamp"`
}

// ConfigFormData represents form data for saving a config.
type ConfigFormData struct {
	Thresholds  ThresholdsData  `json:"thresholds"`
	Excluded    ExcludedData    `json:"excluded"`
	Whitelist   []WhitelistItem `json:"whitelist"`
	DNSLog      bool            `json:"dns_log"`
	DNS         DNSData         `json:"dns"`
	Alerting    AlertingData    `json:"alerting"`
	ThreatIntel ThreatIntelData `json:"threat_intel"`
}

type ThresholdsData struct {
	MinIPConnections      int `json:"min_ip_connections"`
	MinProcessConnections int `json:"min_process_connections"`
	CriticalThreshold     int `json:"critical_threshold"`
	HighThreshold         int `json:"high_threshold"`
}

type ExcludedData struct {
	PIDs      []int    `json:"pids"`
	Processes []string `json:"processes"`
}

type WhitelistItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

type DNSData struct {
	LookupConcurrency int `json:"lookup_concurrency"`
}

type AlertingData struct {
	WebhookURL string `json:"webhook_url"`
	Enabled    bool  `json:"enabled"`
}

type ThreatIntelData struct {
	Enabled      bool `json:"enabled"`
	RefreshIntvl int  `json:"refresh_interval"`
	APIKey       string `json:"api_key"`
	Timeout      int  `json:"timeout"`
	FeedURL      string `json:"feed_url"`
}

type SnapshotResponse struct {
	Name         string `json:"name"`
	Timestamp    string `json:"timestamp"`
	SnapshotPath string `json:"snapshot_path"`
}

type ConfigResponse struct {
	Thresholds  ThresholdsData  `json:"thresholds"`
	Excluded    ExcludedData    `json:"excluded"`
	Whitelist   []WhitelistItem `json:"whitelist"`
	DNSLog      bool            `json:"dns_log"`
	DNS         DNSData         `json:"dns"`
	Alerting    AlertingData    `json:"alerting"`
	ThreatIntel ThreatIntelData `json:"threat_intel"`
}

// NewApp creates a new App application struct.
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	configFile := "config.json"
	if data, err := os.ReadFile("wails.json"); err == nil {
		var wailsCfg struct {
			ConfigFile string `json:"config_file"`
			OutputDir  string `json:"output_dir"`
		}
		json.Unmarshal(data, &wailsCfg)
		if wailsCfg.ConfigFile != "" {
			configFile = wailsCfg.ConfigFile
		}
		a.outputDir = wailsCfg.OutputDir
	}

	if !filepath.IsAbs(configFile) {
		exe, err := os.Executable()
		if err == nil {
			configFile = filepath.Join(filepath.Dir(exe), configFile)
		}
	}
	a.configPath = configFile

	if a.outputDir == "" {
		exe, err := os.Executable()
		if err == nil {
			a.outputDir = filepath.Dir(exe)
		}
	}

	a.configMgr = configmgr.NewConfigManager("config_snapshots")

	cfg, err := config.Load(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config: %v\n", err)
		defaultCfg := config.Defaults()
		cfg = &defaultCfg
	}
	a.config = cfg

	baselineFile := "baseline.json"
	if data, err := os.ReadFile("wails.json"); err == nil {
		var wailsCfg struct {
			BaselineFile string `json:"baseline_file"`
		}
		json.Unmarshal(data, &wailsCfg)
		if wailsCfg.BaselineFile != "" {
			baselineFile = wailsCfg.BaselineFile
		}
	}
	if !filepath.IsAbs(baselineFile) {
		exe, err := os.Executable()
		if err == nil {
			baselineFile = filepath.Join(filepath.Dir(exe), baselineFile)
		}
	}
	a.lastBaseline = baselineFile
}

// RunScan performs a full network scan.
func (a *App) RunScan() (*ScanResult, error) {
	if a.config == nil {
		return nil, fmt.Errorf("no config loaded")
	}

	sysInfo, err := systeminfo.Gather()
	if err != nil {
		return nil, fmt.Errorf("failed to gather system info: %w", err)
	}

	conns, procs, secInfo, err := scanner.ScanAll(a.config)
	if err != nil {
		return nil, fmt.Errorf("failed to scan: %w", err)
	}

	dnsConcurrency := a.config.DNS.LookupConcurrency
	if dnsConcurrency <= 0 {
		dnsConcurrency = 10
	}
	dns.ResolveConnectionsDNS(conns, dnsConcurrency)

	tiDB := threatintel.NewThreatIntelDB()
	tiDB.AddIOCs(threatintel.KnownC2IPs)

	if a.config.ThreatIntel.Enabled {
		timeout := time.Duration(a.config.ThreatIntel.Timeout) * time.Second
		feedClient := threatintel.NewThreatFoxFeedClient(a.config.ThreatIntel.APIKey, timeout)
		cacheMgr := threatintel.NewFeedCacheManager(feedClient, 1*time.Hour)
		liveIOCs, err := cacheMgr.GetIOCs()
		if err == nil && len(liveIOCs) > 0 {
			tiDB.AddIOCs(liveIOCs)
		}
	}

	c2Client := threatintel.NewC2IntelFeedsClient(time.Duration(a.config.ThreatIntel.Timeout) * time.Second)
	c2IOCs, err := c2Client.FetchAllIOCs()
	if err == nil && len(c2IOCs) > 0 {
		tiDB.AddIOCs(c2IOCs)
	}

	risks := scanner.AssessConnectionRiskWithThreatIntel(conns, secInfo, a.config, tiDB)

	// Baseline comparison
	var baselineDiff *BaselineResp
	var currentEntries []baseline.Entry
	for _, c := range conns {
		currentEntries = append(currentEntries, baseline.Entry{
			ProcessID:  c.ProcessID,
			Process:    c.Process,
			LocalAddr:  c.LocalAddr,
			LocalPort:  c.LocalPort,
			RemoteAddr: c.RemoteAddr,
			RemotePort: c.RemotePort,
			State:      c.State,
		})
	}
	if prevSnap, err := baseline.Load(a.lastBaseline); err == nil && prevSnap != nil {
		diff := baseline.Diff(currentEntries, prevSnap)
		baselineDiff = &BaselineResp{
			New:         toBaseEntries(diff.New),
			Gone:        toBaseEntries(diff.Gone),
			Unchanged:   len(diff.Unchanged),
			BaselineAge: diff.BaselineAge.Round(time.Second).String(),
		}
	}

	// DNS capture
	var dnsQueries *DNSQueriesResp
	if a.config.DNSLog {
		captureResult, err := dns.CaptureDNSQueries(a.config, sysInfo.Hostname)
		if err == nil && captureResult != nil {
			ipToDomain := dns.DNSQueriesToIPMap(captureResult.Queries)
			for i := range conns {
				c := &conns[i]
				if c.DNSName == "" && c.RemoteAddr != "" {
					if domain, ok := ipToDomain[c.RemoteAddr]; ok {
						c.DNSName = domain
					}
				}
			}
			dnsQueries = &DNSQueriesResp{
				Queries: toDNSDetails(captureResult.Queries),
				Method:  captureResult.CaptureMethod,
			}
		}
	}

	data := report.Data{
		System:      sysInfo,
		Connections: conns,
		Processes:   procs,
		Risks:       risks,
		Security:    secInfo,
	}
	findings := report.Summarize(data)

	result := &ScanResult{
		System: &SystemInfoResp{
			Hostname:   sysInfo.Hostname,
			OSPlatform: sysInfo.OSPlatform,
			LocalIPs:   sysInfo.LocalIPs,
		},
		Connections: toConns(conns),
		Processes:   toProcs(procs),
		Risks:       toRisks(risks),
		Security:    toSecs(secInfo),
		Baseline:    baselineDiff,
		Findings:    toFindings(findings),
		DNSQueries:  dnsQueries,
		ScanTime:    time.Now().Format("2006-01-02 15:04:05"),
		DNSLookups:  countDNS(conns),
	}

	if err := baseline.Save(a.lastBaseline, sysInfo.Hostname, currentEntries); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save baseline: %v\n", err)
	}

	ts := time.Now().Format("20060102_150405")
	mdFile := fmt.Sprintf("%s/network_sentinel_%s_%s.md", a.outputDir, sysInfo.Hostname, ts)
	jsonFile := fmt.Sprintf("%s/network_sentinel_%s_%s.json", a.outputDir, sysInfo.Hostname, ts)

	if err := report.GenerateMarkdown(data, mdFile); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to generate report: %v\n", err)
	}
	if err := report.GenerateJSON(data, jsonFile); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to generate json: %v\n", err)
	}

	a.lastScan = result
	a.lastReport = mdFile
	return result, nil
}

// GetLastScan returns the last scan result.
func (a *App) GetLastScan() *ScanResult {
	return a.lastScan
}

// GetLastReportPath returns the path to the last generated markdown report.
func (a *App) GetLastReportPath() string {
	return a.lastReport
}

// GetBaselinePath returns the baseline file path.
func (a *App) GetBaselinePath() string {
	return a.lastBaseline
}

// LoadBaseline loads and returns the baseline comparison.
func (a *App) LoadBaseline() (*BaselineResp, error) {
	snap, err := baseline.Load(a.lastBaseline)
	if err != nil {
		return nil, fmt.Errorf("failed to load baseline: %w", err)
	}
	if a.config == nil {
		return nil, fmt.Errorf("no config loaded")
	}
	conns, _, _, err := scanner.ScanAll(a.config)
	if err != nil {
		return nil, fmt.Errorf("failed to scan: %w", err)
	}
	var currentEntries []baseline.Entry
	for _, c := range conns {
		currentEntries = append(currentEntries, baseline.Entry{
			ProcessID:  c.ProcessID,
			Process:    c.Process,
			LocalAddr:  c.LocalAddr,
			LocalPort:  c.LocalPort,
			RemoteAddr: c.RemoteAddr,
			RemotePort: c.RemotePort,
			State:      c.State,
		})
	}
	diff := baseline.Diff(currentEntries, snap)
	return &BaselineResp{
		New:         toBaseEntries(diff.New),
		Gone:        toBaseEntries(diff.Gone),
		Unchanged:   len(diff.Unchanged),
		BaselineAge: diff.BaselineAge.Round(time.Second).String(),
	}, nil
}

// GetCurrentConfig returns the current config.
func (a *App) GetCurrentConfig() *ConfigResponse {
	if a.config == nil {
		c := config.Defaults()
		return a.configToResponse(&c)
	}
	return a.configToResponse(a.config)
}

// ReloadConfig reloads config from the config file.
func (a *App) ReloadConfig() (*ConfigResponse, error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to reload config: %w", err)
	}
	a.config = cfg
	return a.configToResponse(cfg), nil
}

// SaveConfig saves the config from form data.
func (a *App) SaveConfig(data ConfigFormData) error {
	cfg := &config.Config{}
	*cfg = config.Defaults()
	cfg.Thresholds = config.Thresholds{
		MinIPConnections:      data.Thresholds.MinIPConnections,
		MinProcessConnections: data.Thresholds.MinProcessConnections,
		CriticalThreshold:     data.Thresholds.CriticalThreshold,
		HighThreshold:         data.Thresholds.HighThreshold,
	}
	cfg.Excluded = config.Excluded{
		PIDs:      data.Excluded.PIDs,
		Processes: data.Excluded.Processes,
	}
	cfg.DNSLog = data.DNSLog
	cfg.DNS = config.DNSConfig{
		LookupConcurrency: data.DNS.LookupConcurrency,
	}
	cfg.Alerting = config.Alerting{
		WebhookURL: data.Alerting.WebhookURL,
		Enabled:    data.Alerting.Enabled,
	}
	cfg.ThreatIntel = config.ThreatIntelConfig{
		Enabled:      data.ThreatIntel.Enabled,
		RefreshIntvl: data.ThreatIntel.RefreshIntvl,
		APIKey:       data.ThreatIntel.APIKey,
		Timeout:      data.ThreatIntel.Timeout,
		FeedURL:      data.ThreatIntel.FeedURL,
	}
	for _, w := range data.Whitelist {
		cfg.Whitelist = append(cfg.Whitelist, config.WhitelistedIP{
			IP:      w.IP,
			Comment: w.Comment,
		})
	}
	_, err := a.configMgr.SaveConfig(cfg, a.configPath)
	if err != nil {
		return err
	}
	a.config = cfg
	return nil
}

// ExportConfig exports the current config to a timestamped file.
func (a *App) ExportConfig(destDir string) (string, error) {
	if a.config == nil {
		return "", fmt.Errorf("no config loaded")
	}
	return a.configMgr.ExportConfig(a.config, destDir)
}

// CreateSnapshot creates a named snapshot of the current config.
func (a *App) CreateSnapshot(name string) (*SnapshotResponse, error) {
	if a.config == nil {
		return nil, fmt.Errorf("no config loaded")
	}
	snap, err := a.configMgr.CreateSnapshot(a.config, name)
	if err != nil {
		return nil, err
	}
	return &SnapshotResponse{
		Name:         snap.Name,
		Timestamp:    snap.Timestamp.Format("2006-01-02 15:04:05"),
		SnapshotPath: snap.SnapshotPath,
	}, nil
}

// ListSnapshots returns all saved snapshots.
func (a *App) ListSnapshots() ([]SnapshotResponse, error) {
	snapshots, err := a.configMgr.ListSnapshots()
	if err != nil {
		return nil, err
	}
	var responses []SnapshotResponse
	for _, s := range snapshots {
		responses = append(responses, SnapshotResponse{
			Name:         s.Name,
			Timestamp:    s.Timestamp.Format("2006-01-02 15:04:05"),
			SnapshotPath: s.SnapshotPath,
		})
	}
	return responses, nil
}

// LoadSnapshot loads a snapshot and returns it as the current config.
func (a *App) LoadSnapshot(filename string) (*ConfigResponse, error) {
	cfg, err := a.configMgr.LoadSnapshot(filename)
	if err != nil {
		return nil, err
	}
	a.config = cfg
	return a.configToResponse(cfg), nil
}

// DeleteSnapshot deletes a snapshot by filename.
func (a *App) DeleteSnapshot(filename string) error {
	return a.configMgr.DeleteSnapshot(filename)
}

// SaveCurrentConfigPath returns the current config file path.
func (a *App) SaveCurrentConfigPath() string {
	return a.configPath
}

func (a *App) configToResponse(cfg *config.Config) *ConfigResponse {
	if cfg == nil {
		c := config.Defaults()
		cfg = &c
	}
	return &ConfigResponse{
		Thresholds: ThresholdsData{
			MinIPConnections:      cfg.Thresholds.MinIPConnections,
			MinProcessConnections: cfg.Thresholds.MinProcessConnections,
			CriticalThreshold:     cfg.Thresholds.CriticalThreshold,
			HighThreshold:         cfg.Thresholds.HighThreshold,
		},
		Excluded: ExcludedData{
			PIDs:      cfg.Excluded.PIDs,
			Processes: cfg.Excluded.Processes,
		},
		Whitelist: func() []WhitelistItem {
			if cfg.Whitelist == nil {
				return []WhitelistItem{}
			}
			items := make([]WhitelistItem, len(cfg.Whitelist))
			for i, w := range cfg.Whitelist {
				items[i] = WhitelistItem{IP: w.IP, Comment: w.Comment}
			}
			return items
		}(),
		DNSLog: cfg.DNSLog,
		DNS: DNSData{
			LookupConcurrency: cfg.DNS.LookupConcurrency,
		},
		Alerting: AlertingData{
			WebhookURL: cfg.Alerting.WebhookURL,
			Enabled:    cfg.Alerting.Enabled,
		},
		ThreatIntel: ThreatIntelData{
			Enabled:      cfg.ThreatIntel.Enabled,
			RefreshIntvl: cfg.ThreatIntel.RefreshIntvl,
			APIKey:       cfg.ThreatIntel.APIKey,
			Timeout:      cfg.ThreatIntel.Timeout,
			FeedURL:      cfg.ThreatIntel.FeedURL,
		},
	}
}

// Helper functions
func toConns(conns []scanner.Connection) []ConnectionResp {
	res := make([]ConnectionResp, len(conns))
	for i, c := range conns {
		res[i] = ConnectionResp{
			ProcessID:  c.ProcessID,
			Process:    c.Process,
			Executable: c.Executable,
			LocalAddr:  c.LocalAddr,
			LocalPort:  c.LocalPort,
			RemoteAddr: c.RemoteAddr,
			RemotePort: c.RemotePort,
			Protocol:   c.Protocol,
			State:      c.State,
			Direction:  c.Direction,
			DNSName:    c.DNSName,
		}
	}
	return res
}

func toProcs(procs []scanner.ProcessEntry) []ProcessResp {
	res := make([]ProcessResp, len(procs))
	for i, p := range procs {
		res[i] = ProcessResp{PID: p.PID, Name: p.Name}
	}
	return res
}

func toRisks(risks []scanner.ConnectionRisk) []RiskResp {
	res := make([]RiskResp, len(risks))
	for i, r := range risks {
		res[i] = RiskResp{
			ProcessID:     r.ProcessID,
			Process:       r.Process,
			Executable:    r.Executable,
			LocalAddr:     r.LocalAddr,
			LocalPort:     r.LocalPort,
			RemoteAddr:    r.RemoteAddr,
			RemotePort:    r.RemotePort,
			Protocol:      r.Protocol,
			State:         r.State,
			Direction:     r.Direction,
			DNSName:       r.DNSName,
			RiskLevel:     string(r.RiskLevel),
			RiskReasons:   r.RiskReasons,
			IsSuspicious:  r.IsSuspicious,
			IsWhitelisted: r.IsWhitelisted,
		}
	}
	return res
}

func toSecs(secInfo map[int]processinfo.Info) []SecurityResp {
	var res []SecurityResp
	for _, info := range secInfo {
		res = append(res, SecurityResp{
			PID:        info.PID,
			Name:       info.Name,
			ExePath:    info.ExePath,
			PrivLevel:  string(info.PrivLevel),
			IsSigned:   info.IsSigned,
			IsElevated: info.PrivLevel == processinfo.Elevated || info.PrivLevel == processinfo.SYSTEM,
			Username:   info.Username,
		})
	}
	return res
}

func toBaseEntries(entries []baseline.Entry) []BaseEntryResp {
	res := make([]BaseEntryResp, len(entries))
	for i, e := range entries {
		res[i] = BaseEntryResp{
			ProcessID:  e.ProcessID,
			Process:    e.Process,
			LocalAddr:  e.LocalAddr,
			LocalPort:  e.LocalPort,
			RemoteAddr: e.RemoteAddr,
			RemotePort: e.RemotePort,
			State:      e.State,
		}
	}
	return res
}

func toFindings(f report.Findings) *FindingsResp {
	return &FindingsResp{
		TotalOutbound:       f.TotalOutbound,
		ExternalEndpoints:   f.ExternalEndpoints,
		SuspiciousPorts:     f.SuspiciousPorts,
		SuspiciousProcs:     f.SuspiciousProcs,
		HighestRisk:         string(f.HighestRisk),
		CriticalCount:       f.CriticalCount,
		HighCount:           f.HighCount,
		MediumCount:         f.MediumCount,
		LowCount:            f.LowCount,
		PrivEscalationCount: f.PrivEscalationCount,
		WhitelistedCount:    f.WhitelistedCount,
	}
}

func toDNSDetails(queries []dns.Query) []DNSQDetail {
	res := make([]DNSQDetail, len(queries))
	for i, q := range queries {
		res[i] = DNSQDetail{
			PID:       q.PID,
			Process:   q.Process,
			QueryName: q.QueryName,
			Timestamp: q.Timestamp.Format("2006-01-02 15:04:05"),
		}
	}
	return res
}

func countDNS(conns []scanner.Connection) int {
	count := 0
	for _, c := range conns {
		if c.DNSName != "" {
			count++
		}
	}
	return count
}

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:  "Network Sentinel",
		Width:  1200,
		Height: 800,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 15, G: 23, B: 42, A: 255},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		fmt.Println("Error:", err.Error())
	}
}
