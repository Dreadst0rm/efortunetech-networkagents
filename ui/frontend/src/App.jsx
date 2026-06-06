import { useState, useEffect, useCallback } from 'react';
import './App.css';
import { RunScan, GetCurrentConfig, SaveConfig, ReloadConfig, ExportConfig, CreateSnapshot, ListSnapshots, LoadSnapshot, DeleteSnapshot, GetLastReportPath, SaveCurrentConfigPath, GetLastScan, LoadBaseline } from '../wailsjs/go/main/App';
import { EventsEmit } from '../wailsjs/runtime';

const api = {
  RunScan,
  GetCurrentConfig,
  SaveConfig,
  ReloadConfig,
  ExportConfig,
  CreateSnapshot,
  ListSnapshots,
  LoadSnapshot,
  DeleteSnapshot,
  GetLastReportPath,
  SaveCurrentConfigPath,
  GetLastScan,
  LoadBaseline,
};

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [config, setConfig] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [status, setStatus] = useState('');
  const [snapshots, setSnapshots] = useState([]);
  const [snapshotName, setSnapshotName] = useState('');
  const [exportDir, setExportDir] = useState('.');
  const [exportPath, setExportPath] = useState('');
  const [whitelistIP, setWhitelistIP] = useState('');
  const [whitelistComment, setWhitelistComment] = useState('');
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  const fetchConfig = useCallback(async () => {
    try {
      const resp = await api.GetCurrentConfig();
      setConfig(resp);
      setLoading(false);
    } catch (err) {
      setStatus(`Error loading config: ${err}`);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  const handleRunScan = async () => {
    setScanning(true);
    setStatus('');
    setScanResult(null);
    try {
      const result = await api.RunScan();
      setScanResult(result);
      setStatus(`Scan complete at ${result.scan_time}`);
    } catch (err) {
      setStatus(`Scan failed: ${err}`);
    }
    setScanning(false);
  };

  const handleSave = async () => {
    setStatus('');
    try {
      await api.SaveConfig(config);
      setStatus('Config saved successfully!');
    } catch (err) {
      setStatus(`Save failed: ${err}`);
    }
  };

  const handleExport = async () => {
    setStatus('');
    setExportPath('');
    try {
      const path = await api.ExportConfig(exportDir);
      setExportPath(path);
      setStatus(`Config exported to: ${path}`);
    } catch (err) {
      setStatus(`Export failed: ${err}`);
    }
  };

  const handleCreateSnapshot = async () => {
    setStatus('');
    try {
      const snap = await api.CreateSnapshot(snapshotName);
      setStatus(`Snapshot "${snap.name}" created!`);
      fetchSnapshots();
      setSnapshotName('');
    } catch (err) {
      setStatus(`Snapshot failed: ${err}`);
    }
  };

  const fetchSnapshots = async () => {
    try {
      const list = await api.ListSnapshots();
      setSnapshots(list);
    } catch (err) {
      setStatus(`Failed to load snapshots: ${err}`);
    }
  };

  const handleLoadSnapshot = async (filename) => {
    setStatus('');
    try {
      const cfg = await api.LoadSnapshot(filename);
      setConfig(cfg);
      setStatus(`Loaded snapshot: ${filename}`);
    } catch (err) {
      setStatus(`Load failed: ${err}`);
    }
  };

  const handleDeleteSnapshot = async (filename) => {
    setStatus('');
    try {
      await api.DeleteSnapshot(filename);
      fetchSnapshots();
      setStatus(`Snapshot deleted: ${filename}`);
    } catch (err) {
      setStatus(`Delete failed: ${err}`);
    }
  };

  const handleReload = async () => {
    setStatus('');
    try {
      const cfg = await api.ReloadConfig();
      setConfig(cfg);
      setStatus('Config reloaded from disk!');
    } catch (err) {
      setStatus(`Reload failed: ${err}`);
    }
  };

  const updateField = (section, field, value) => {
    setConfig(prev => ({
      ...prev,
      [section]: { ...prev[section], [field]: value }
    }));
  };

  const addWhitelistEntry = () => {
    if (!whitelistIP.trim()) return;
    setConfig(prev => ({
      ...prev,
      whitelist: [...prev.whitelist, { ip: whitelistIP.trim(), comment: whitelistComment.trim() }]
    }));
    setWhitelistIP('');
    setWhitelistComment('');
  };

  const removeWhitelistEntry = (index) => {
    setConfig(prev => ({
      ...prev,
      whitelist: prev.whitelist.filter((_, i) => i !== index)
    }));
  };

  const updateWhitelistEntry = (index, field, value) => {
    setConfig(prev => {
      const wl = [...prev.whitelist];
      wl[index] = { ...wl[index], [field]: value };
      return { ...prev, whitelist: wl };
    });
  };

  if (loading) {
    return (
      <div id="app">
        <div className="loading">Loading Network Sentinel...</div>
      </div>
    );
  }

  const riskColor = (level) => {
    switch (level) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#3b82f6';
      default: return '#64748b';
    }
  };

  return (
    <div id="app">
      <header className="header">
        <h1>Network Sentinel</h1>
        <p>Security Monitoring & Configuration</p>
        <button className="btn-secondary" onClick={handleReload}>
          Reload Config
        </button>
      </header>

      <div className="tabs">
        <button className={activeTab === 'dashboard' ? 'tab active' : 'tab'} onClick={() => setActiveTab('dashboard')}>
          Dashboard
        </button>
        <button className={activeTab === 'connections' ? 'tab active' : 'tab'} onClick={() => setActiveTab('connections')}>
          Connections
        </button>
        <button className={activeTab === 'risks' ? 'tab active' : 'tab'} onClick={() => setActiveTab('risks')}>
          Risk Analysis
        </button>
        <button className={activeTab === 'security' ? 'tab active' : 'tab'} onClick={() => setActiveTab('security')}>
          Security Context
        </button>
        <button className={activeTab === 'dns' ? 'tab active' : 'tab'} onClick={() => setActiveTab('dns')}>
          DNS
        </button>
        <button className={activeTab === 'baseline' ? 'tab active' : 'tab'} onClick={() => setActiveTab('baseline')}>
          Baseline
        </button>
        <button className={activeTab === 'config' ? 'tab active' : 'tab'} onClick={() => setActiveTab('config')}>
          Config
        </button>
        <button className={activeTab === 'snapshots' ? 'tab active' : 'tab'} onClick={() => setActiveTab('snapshots')}>
          Snapshots
        </button>
        <button className={activeTab === 'export' ? 'tab active' : 'tab'} onClick={() => setActiveTab('export')}>
          Export
        </button>
      </div>

      <div className="content">
        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <div className="tab-content">
            <h2>Scan Dashboard</h2>
            <button className="btn-primary" onClick={handleRunScan} disabled={scanning}>
              {scanning ? 'Scanning...' : 'Run Full Scan'}
            </button>

            {status && <div className={`status ${status.includes('failed') || status.includes('Failed') ? 'status-error' : 'status-success'}`}>{status}</div>}

            {scanResult && (
              <>
                <div className="scan-summary">
                  <h3>Scan Summary</h3>
                  <div className="summary-grid">
                    <div className="summary-card">
                      <div className="summary-value">{scanResult.connections?.length || 0}</div>
                      <div className="summary-label">Total Connections</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-value">{scanResult.findings?.total_outbound || 0}</div>
                      <div className="summary-label">Outbound</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-value">{scanResult.findings?.external_endpoints || 0}</div>
                      <div className="summary-label">External Endpoints</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-value" style={{ color: riskColor(scanResult.findings?.highest_risk) }}>
                        {(scanResult.findings?.critical_count || 0) + (scanResult.findings?.high_count || 0)}
                      </div>
                      <div className="summary-label">Critical + High</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-value">{scanResult.findings?.priv_esc_count || 0}</div>
                      <div className="summary-label">Priv Escalation</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-value">{scanResult.dns_lookups || 0}</div>
                      <div className="summary-label">DNS Resolved</div>
                    </div>
                  </div>
                </div>

                {scanResult.findings && (
                  <div className="findings-section">
                    <h3>Risk Breakdown</h3>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Risk Level</th>
                          <th>Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td><span className="risk-badge" style={{ background: '#ef4444' }}>CRITICAL</span></td>
                          <td>{scanResult.findings.critical_count}</td>
                        </tr>
                        <tr>
                          <td><span className="risk-badge" style={{ background: '#f97316' }}>HIGH</span></td>
                          <td>{scanResult.findings.high_count}</td>
                        </tr>
                        <tr>
                          <td><span className="risk-badge" style={{ background: '#eab308' }}>MEDIUM</span></td>
                          <td>{scanResult.findings.medium_count}</td>
                        </tr>
                        <tr>
                          <td><span className="risk-badge" style={{ background: '#3b82f6' }}>LOW</span></td>
                          <td>{scanResult.findings.low_count}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                )}

                {scanResult.system && (
                  <div className="system-info">
                    <h3>System Info</h3>
                    <p><strong>Hostname:</strong> {scanResult.system.hostname}</p>
                    <p><strong>OS:</strong> {scanResult.system.os_platform}</p>
                    <p><strong>Local IPs:</strong> {scanResult.system.local_ips?.join(', ')}</p>
                  </div>
                )}

                {scanResult.baseline && (
                  <div className="baseline-section">
                    <h3>Baseline Comparison</h3>
                    <p><strong>Previous baseline age:</strong> {scanResult.baseline.baseline_age}</p>
                    <p><strong>New connections:</strong> {scanResult.baseline.new?.length || 0}</p>
                    <p><strong>Disappeared:</strong> {scanResult.baseline.gone?.length || 0}</p>
                    <p><strong>Unchanged:</strong> {scanResult.baseline.unchanged}</p>
                  </div>
                )}

                {scanResult.security && scanResult.security.length > 0 && (
                  <div className="priv-esc-section">
                    <h3>Privilege Escalation Risks</h3>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>PID</th>
                          <th>Process</th>
                          <th>Privilege</th>
                          <th>Signed</th>
                          <th>Path</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanResult.security.filter(s => s.is_elevated && !s.is_signed).map((s, i) => (
                          <tr key={i}>
                            <td>{s.pid}</td>
                            <td>{s.name}</td>
                            <td>{s.priv_level}</td>
                            <td>{s.is_signed ? 'Yes' : 'No'}</td>
                            <td>{s.exe_path}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {scanResult.connections && scanResult.connections.length > 0 && (
                  <div className="top-processes">
                    <h3>Top Processes by Connections</h3>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Process</th>
                          <th>PID</th>
                          <th>Connections</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(() => {
                          const counts = {};
                          scanResult.connections.forEach(c => {
                            counts[c.process] = (counts[c.process] || 0) + 1;
                          });
                          const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
                          return sorted.map(([name, count], i) => {
                            const pid = scanResult.connections.find(c => c.process === name)?.process_id;
                            return (
                              <tr key={i}>
                                <td>{name}</td>
                                <td>{pid}</td>
                                <td>{count}</td>
                              </tr>
                            );
                          });
                        })()}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Connections Tab */}
        {activeTab === 'connections' && (
          <div className="tab-content">
            <h2>Network Connections</h2>
            {!scanResult && <p className="empty">Run a scan first to see connections.</p>}
            {scanResult && scanResult.connections?.length === 0 && <p className="empty">No connections found.</p>}
            {scanResult && scanResult.connections?.length > 0 && (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Process</th>
                    <th>PID</th>
                    <th>Local</th>
                    <th>Remote</th>
                    <th>Port</th>
                    <th>DNS Name</th>
                    <th>State</th>
                    <th>Direction</th>
                  </tr>
                </thead>
                <tbody>
                  {scanResult.connections.map((c, i) => (
                    <tr key={i}>
                      <td>{c.process}</td>
                      <td>{c.process_id}</td>
                      <td>{c.local_addr}:{c.local_port}</td>
                      <td>{c.remote_addr}</td>
                      <td>{c.remote_port}</td>
                      <td>{c.dns_name || '-'}</td>
                      <td>{c.state}</td>
                      <td>{c.direction}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Risk Analysis Tab */}
        {activeTab === 'risks' && (
          <div className="tab-content">
            <h2>Risk Analysis</h2>
            {!scanResult && <p className="empty">Run a scan first to see risk analysis.</p>}
            {scanResult && scanResult.risks?.length === 0 && <p className="empty">No risky connections found.</p>}
            {scanResult && scanResult.risks?.length > 0 && (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Level</th>
                    <th>Process</th>
                    <th>Remote</th>
                    <th>Port</th>
                    <th>DNS Name</th>
                    <th>Reasons</th>
                    <th>Whitelisted</th>
                  </tr>
                </thead>
                <tbody>
                  {scanResult.risks.map((r, i) => (
                    <tr key={i} style={{ borderLeft: `3px solid ${riskColor(r.risk_level)}` }}>
                      <td><span className="risk-badge" style={{ background: riskColor(r.risk_level) }}>{r.risk_level}</span></td>
                      <td>{r.process}</td>
                      <td>{r.remote_addr}</td>
                      <td>{r.remote_port}</td>
                      <td>{r.dns_name || '-'}</td>
                      <td>{r.risk_reasons?.join(', ')}</td>
                      <td>{r.is_whitelisted ? 'Yes' : 'No'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Security Context Tab */}
        {activeTab === 'security' && (
          <div className="tab-content">
            <h2>Security Context</h2>
            {!scanResult && <p className="empty">Run a scan first to see security context.</p>}
            {scanResult && scanResult.security?.length === 0 && <p className="empty">No process security data.</p>}
            {scanResult && scanResult.security?.length > 0 && (
              <>
                <h3>Privilege Escalation Risks</h3>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>PID</th>
                      <th>Process</th>
                      <th>Privilege</th>
                      <th>Signed</th>
                      <th>Integrity</th>
                      <th>Path</th>
                      <th>User</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.security.filter(s => s.is_elevated || !s.is_signed).map((s, i) => (
                      <tr key={i} style={{ borderLeft: `3px solid ${s.is_elevated && !s.is_signed ? '#ef4444' : '#64748b'}` }}>
                        <td>{s.pid}</td>
                        <td>{s.name}</td>
                        <td>{s.priv_level}</td>
                        <td>{s.is_signed ? 'Yes' : 'No'}</td>
                        <td>{s.is_elevated ? 'Elevated' : 'Standard'}</td>
                        <td>{s.exe_path}</td>
                        <td>{s.username}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
        )}

        {/* DNS Tab */}
        {activeTab === 'dns' && (
          <div className="tab-content">
            <h2>DNS Queries</h2>
            {!scanResult?.dns_queries && <p className="empty">Run a scan with DNS logging enabled.</p>}
            {scanResult?.dns_queries && scanResult.dns_queries.queries?.length === 0 && <p className="empty">No DNS queries captured.</p>}
            {scanResult?.dns_queries && scanResult.dns_queries.queries?.length > 0 && (
              <>
                <p><strong>Capture Method:</strong> {scanResult.dns_queries.method}</p>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Process</th>
                      <th>PID</th>
                      <th>Query</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.dns_queries.queries.map((q, i) => (
                      <tr key={i}>
                        <td>{q.process || `PID:${q.pid}`}</td>
                        <td>{q.pid}</td>
                        <td>{q.query_name}</td>
                        <td>{q.timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
        )}

        {/* Baseline Tab */}
        {activeTab === 'baseline' && (
          <div className="tab-content">
            <h2>Baseline Comparison</h2>
            <button className="btn-primary" onClick={handleRunScan}>
              Rescan & Compare
            </button>
            {status && <div className={`status ${status.includes('failed') || status.includes('Failed') ? 'status-error' : 'status-success'}`}>{status}</div>}
            {!scanResult?.baseline && <p className="empty">Run a scan to see baseline comparison.</p>}
            {scanResult?.baseline && (
              <>
                <div className="baseline-summary">
                  <p><strong>Previous baseline age:</strong> {scanResult.baseline.baseline_age}</p>
                  <p><strong>New connections:</strong> {scanResult.baseline.new?.length || 0}</p>
                  <p><strong>Disappeared:</strong> {scanResult.baseline.gone?.length || 0}</p>
                  <p><strong>Unchanged:</strong> {scanResult.baseline.unchanged}</p>
                </div>
                {scanResult.baseline.new?.length > 0 && (
                  <>
                    <h3>New Connections</h3>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Process</th>
                          <th>PID</th>
                          <th>Remote</th>
                          <th>Port</th>
                          <th>State</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanResult.baseline.new.map((e, i) => (
                          <tr key={i}>
                            <td>{e.process}</td>
                            <td>{e.pid}</td>
                            <td>{e.remote_addr}</td>
                            <td>{e.remote_port}</td>
                            <td>{e.state}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
                {scanResult.baseline.gone?.length > 0 && (
                  <>
                    <h3>Disappeared Connections</h3>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Process</th>
                          <th>PID</th>
                          <th>Remote</th>
                          <th>Port</th>
                          <th>State</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanResult.baseline.gone.map((e, i) => (
                          <tr key={i}>
                            <td>{e.process}</td>
                            <td>{e.pid}</td>
                            <td>{e.remote_addr}</td>
                            <td>{e.remote_port}</td>
                            <td>{e.state}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </>
            )}
          </div>
        )}

        {/* Config Tab */}
        {activeTab === 'config' && (
          <div className="tab-content">
            <h2>Configuration</h2>

            <div className="tabs-small">
              <button className={activeTab === 'config' ? 'tab-small active' : 'tab-small'} onClick={() => setActiveTab('config')}>
                Thresholds
              </button>
              <button className={'tab-small'} onClick={() => { setActiveTab('config'); /* inline scroll */ }}>
                Exclusions
              </button>
              <button className={'tab-small'} onClick={() => { setActiveTab('config'); }}>
                Whitelist
              </button>
              <button className={'tab-small'} onClick={() => { setActiveTab('config'); }}>
                DNS
              </button>
              <button className={'tab-small'} onClick={() => { setActiveTab('config'); }}>
                Alerting
              </button>
              <button className={'tab-small'} onClick={() => { setActiveTab('config'); }}>
                Threat Intel
              </button>
            </div>

            <div className="form-group">
              <label>Min IP Connections</label>
              <input
                type="number"
                value={config.thresholds.min_ip_connections}
                onChange={e => updateField('thresholds', 'min_ip_connections', parseInt(e.target.value) || 0)}
              />
              <span className="hint">Minimum unique IPs to flag</span>
            </div>
            <div className="form-group">
              <label>Min Process Connections</label>
              <input
                type="number"
                value={config.thresholds.min_process_connections}
                onChange={e => updateField('thresholds', 'min_process_connections', parseInt(e.target.value) || 0)}
              />
            </div>
            <div className="form-group">
              <label>Critical Threshold</label>
              <input
                type="number"
                value={config.thresholds.critical_threshold}
                onChange={e => updateField('thresholds', 'critical_threshold', parseInt(e.target.value) || 1)}
              />
            </div>
            <div className="form-group">
              <label>High Threshold</label>
              <input
                type="number"
                value={config.thresholds.high_threshold}
                onChange={e => updateField('thresholds', 'high_threshold', parseInt(e.target.value) || 1)}
              />
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={config.dns_log}
                  onChange={e => updateField(null, 'dns_log', e.target.checked)}
                />
                Enable DNS Logging
              </label>
            </div>

            <div className="form-group">
              <label>DNS Lookup Concurrency</label>
              <input
                type="number"
                value={config.dns.lookup_concurrency}
                onChange={e => updateField('dns', 'lookup_concurrency', parseInt(e.target.value) || 10)}
              />
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={config.alerting.enabled}
                  onChange={e => updateField('alerting', 'enabled', e.target.checked)}
                />
                Enable Alerting
              </label>
            </div>
            <div className="form-group">
              <label>Webhook URL</label>
              <input
                type="text"
                value={config.alerting.webhook_url}
                onChange={e => updateField('alerting', 'webhook_url', e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={config.threat_intel.enabled}
                  onChange={e => updateField('threat_intel', 'enabled', e.target.checked)}
                />
                Enable Live Threat Intel
              </label>
            </div>
            <div className="form-group">
              <label>API Key</label>
              <input
                type="password"
                value={config.threat_intel.api_key}
                onChange={e => updateField('threat_intel', 'api_key', e.target.value)}
              />
            </div>
            <div className="form-group">
              <label>Refresh Interval (seconds)</label>
              <input
                type="number"
                value={config.threat_intel.refresh_interval}
                onChange={e => updateField('threat_intel', 'refresh_interval', parseInt(e.target.value) || 0)}
              />
            </div>
            <div className="form-group">
              <label>HTTP Timeout (seconds)</label>
              <input
                type="number"
                value={config.threat_intel.timeout}
                onChange={e => updateField('threat_intel', 'timeout', parseInt(e.target.value) || 10)}
              />
            </div>

            <h3>Whitelisted IPs</h3>
            <div className="whitelist-add">
              <input
                type="text"
                placeholder="IP address"
                value={whitelistIP}
                onChange={e => setWhitelistIP(e.target.value)}
              />
              <input
                type="text"
                placeholder="Comment"
                value={whitelistComment}
                onChange={e => setWhitelistComment(e.target.value)}
              />
              <button className="btn-primary" onClick={addWhitelistEntry}>Add</button>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Comment</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {config.whitelist.map((w, i) => (
                  <tr key={i}>
                    <td>
                      <input
                        type="text"
                        value={w.ip}
                        onChange={e => updateWhitelistEntry(i, 'ip', e.target.value)}
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={w.comment}
                        onChange={e => updateWhitelistEntry(i, 'comment', e.target.value)}
                      />
                    </td>
                    <td>
                      <button className="btn-danger" onClick={() => removeWhitelistEntry(i)}>Remove</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Snapshots Tab */}
        {activeTab === 'snapshots' && (
          <div className="tab-content">
            <h2>Configuration Snapshots</h2>
            <div className="snapshot-create">
              <input
                type="text"
                placeholder="Snapshot name"
                value={snapshotName}
                onChange={e => setSnapshotName(e.target.value)}
              />
              <button className="btn-primary" onClick={handleCreateSnapshot}>
                Create Snapshot
              </button>
            </div>
            <button className="btn-secondary" onClick={fetchSnapshots}>
              Refresh Snapshots
            </button>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Timestamp</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {snapshots.map((s, i) => (
                  <tr key={i}>
                    <td>{s.name}</td>
                    <td>{s.timestamp}</td>
                    <td>
                      <button className="btn-primary" onClick={() => handleLoadSnapshot(s.snapshot_path)}>Load</button>
                      <button className="btn-danger" onClick={() => handleDeleteSnapshot(s.snapshot_path)}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {snapshots.length === 0 && <p className="empty">No snapshots yet. Create one above.</p>}
          </div>
        )}

        {/* Export Tab */}
        {activeTab === 'export' && (
          <div className="tab-content">
            <h2>Export Configuration</h2>
            <div className="form-group">
              <label>Export Directory</label>
              <input
                type="text"
                value={exportDir}
                onChange={e => setExportDir(e.target.value)}
                placeholder=". (current directory)"
              />
            </div>
            <button className="btn-primary" onClick={handleExport}>
              Export Config
            </button>
            {exportPath && <p className="export-path">Exported to: {exportPath}</p>}
          </div>
        )}

        {status && activeTab !== 'dashboard' && activeTab !== 'baseline' && (
          <div className={`status ${status.includes('failed') || status.includes('Failed') ? 'status-error' : 'status-success'}`}>{status}</div>
        )}
      </div>

      <footer className="footer">
        <button className="btn-save-all" onClick={handleSave}>
          Save Config
        </button>
      </footer>
    </div>
  );
}

export default App;
