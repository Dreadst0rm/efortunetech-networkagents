export namespace main {
	
	export class AlertingData {
	    webhook_url: string;
	    enabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AlertingData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.webhook_url = source["webhook_url"];
	        this.enabled = source["enabled"];
	    }
	}
	export class BaseEntryResp {
	    pid: number;
	    process: string;
	    local_addr: string;
	    local_port: number;
	    remote_addr: string;
	    remote_port: number;
	    state: string;
	
	    static createFrom(source: any = {}) {
	        return new BaseEntryResp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pid = source["pid"];
	        this.process = source["process"];
	        this.local_addr = source["local_addr"];
	        this.local_port = source["local_port"];
	        this.remote_addr = source["remote_addr"];
	        this.remote_port = source["remote_port"];
	        this.state = source["state"];
	    }
	}
	export class BaselineResp {
	    new: BaseEntryResp[];
	    gone: BaseEntryResp[];
	    unchanged: number;
	    baseline_age: string;
	
	    static createFrom(source: any = {}) {
	        return new BaselineResp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.new = this.convertValues(source["new"], BaseEntryResp);
	        this.gone = this.convertValues(source["gone"], BaseEntryResp);
	        this.unchanged = source["unchanged"];
	        this.baseline_age = source["baseline_age"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ThreatIntelData {
	    enabled: boolean;
	    refresh_interval: number;
	    api_key: string;
	    timeout: number;
	    feed_url: string;
	
	    static createFrom(source: any = {}) {
	        return new ThreatIntelData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.refresh_interval = source["refresh_interval"];
	        this.api_key = source["api_key"];
	        this.timeout = source["timeout"];
	        this.feed_url = source["feed_url"];
	    }
	}
	export class DNSData {
	    lookup_concurrency: number;
	
	    static createFrom(source: any = {}) {
	        return new DNSData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.lookup_concurrency = source["lookup_concurrency"];
	    }
	}
	export class WhitelistItem {
	    ip: string;
	    comment: string;
	
	    static createFrom(source: any = {}) {
	        return new WhitelistItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.comment = source["comment"];
	    }
	}
	export class ExcludedData {
	    pids: number[];
	    processes: string[];
	
	    static createFrom(source: any = {}) {
	        return new ExcludedData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pids = source["pids"];
	        this.processes = source["processes"];
	    }
	}
	export class ThresholdsData {
	    min_ip_connections: number;
	    min_process_connections: number;
	    critical_threshold: number;
	    high_threshold: number;
	
	    static createFrom(source: any = {}) {
	        return new ThresholdsData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.min_ip_connections = source["min_ip_connections"];
	        this.min_process_connections = source["min_process_connections"];
	        this.critical_threshold = source["critical_threshold"];
	        this.high_threshold = source["high_threshold"];
	    }
	}
	export class ConfigFormData {
	    thresholds: ThresholdsData;
	    excluded: ExcludedData;
	    whitelist: WhitelistItem[];
	    dns_log: boolean;
	    dns: DNSData;
	    alerting: AlertingData;
	    threat_intel: ThreatIntelData;
	
	    static createFrom(source: any = {}) {
	        return new ConfigFormData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.thresholds = this.convertValues(source["thresholds"], ThresholdsData);
	        this.excluded = this.convertValues(source["excluded"], ExcludedData);
	        this.whitelist = this.convertValues(source["whitelist"], WhitelistItem);
	        this.dns_log = source["dns_log"];
	        this.dns = this.convertValues(source["dns"], DNSData);
	        this.alerting = this.convertValues(source["alerting"], AlertingData);
	        this.threat_intel = this.convertValues(source["threat_intel"], ThreatIntelData);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ConfigResponse {
	    thresholds: ThresholdsData;
	    excluded: ExcludedData;
	    whitelist: WhitelistItem[];
	    dns_log: boolean;
	    dns: DNSData;
	    alerting: AlertingData;
	    threat_intel: ThreatIntelData;
	
	    static createFrom(source: any = {}) {
	        return new ConfigResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.thresholds = this.convertValues(source["thresholds"], ThresholdsData);
	        this.excluded = this.convertValues(source["excluded"], ExcludedData);
	        this.whitelist = this.convertValues(source["whitelist"], WhitelistItem);
	        this.dns_log = source["dns_log"];
	        this.dns = this.convertValues(source["dns"], DNSData);
	        this.alerting = this.convertValues(source["alerting"], AlertingData);
	        this.threat_intel = this.convertValues(source["threat_intel"], ThreatIntelData);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ConnectionResp {
	    process_id: number;
	    process: string;
	    executable: string;
	    local_addr: string;
	    local_port: number;
	    remote_addr: string;
	    remote_port: number;
	    protocol: string;
	    state: string;
	    direction: string;
	    dns_name: string;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionResp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.process_id = source["process_id"];
	        this.process = source["process"];
	        this.executable = source["executable"];
	        this.local_addr = source["local_addr"];
	        this.local_port = source["local_port"];
	        this.remote_addr = source["remote_addr"];
	        this.remote_port = source["remote_port"];
	        this.protocol = source["protocol"];
	        this.state = source["state"];
	        this.direction = source["direction"];
	        this.dns_name = source["dns_name"];
	    }
	}
	
	export class DNSQDetail {
	    pid: number;
	    process: string;
	    query_name: string;
	    timestamp: string;
	
	    static createFrom(source: any = {}) {
	        return new DNSQDetail(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pid = source["pid"];
	        this.process = source["process"];
	        this.query_name = source["query_name"];
	        this.timestamp = source["timestamp"];
	    }
	}
	export class DNSQueriesResp {
	    queries: DNSQDetail[];
	    method: string;
	
	    static createFrom(source: any = {}) {
	        return new DNSQueriesResp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.queries = this.convertValues(source["queries"], DNSQDetail);
	        this.method = source["method"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class FindingsResp {
	    total_outbound: number;
	    external_endpoints: number;
	    suspicious_ports: number;
	    suspicious_procs: number;
	    highest_risk: string;
	    critical_count: number;
	    high_count: number;
	    medium_count: number;
	    low_count: number;
	    priv_esc_count: number;
	    whitelisted_count: number;
	
	    static createFrom(source: any = {}) {
	        return new FindingsResp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total_outbound = source["total_outbound"];
	        this.external_endpoints = source["external_endpoints"];
	        this.suspicious_ports = source["suspicious_ports"];
	        this.suspicious_procs = source["suspicious_procs"];
	        this.highest_risk = source["highest_risk"];
	        this.critical_count = source["critical_count"];
	        this.high_count = source["high_count"];
	        this.medium_count = source["medium_count"];
	        this.low_count = source["low_count"];
	        this.priv_esc_count = source["priv_esc_count"];
	        this.whitelisted_count = source["whitelisted_count"];
	    }
	}
	export class ProcessResp {
	    pid: number;
	    name: string;
	
	    static createFrom(source: any = {}) {
	        return new ProcessResp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pid = source["pid"];
	        this.name = source["name"];
	    }
	}
	export class RiskResp {
	    process_id: number;
	    process: string;
	    executable: string;
	    local_addr: string;
	    local_port: number;
	    remote_addr: string;
	    remote_port: number;
	    protocol: string;
	    state: string;
	    direction: string;
	    dns_name: string;
	    risk_level: string;
	    risk_reasons: string[];
	    is_suspicious: boolean;
	    is_whitelisted: boolean;
	
	    static createFrom(source: any = {}) {
	        return new RiskResp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.process_id = source["process_id"];
	        this.process = source["process"];
	        this.executable = source["executable"];
	        this.local_addr = source["local_addr"];
	        this.local_port = source["local_port"];
	        this.remote_addr = source["remote_addr"];
	        this.remote_port = source["remote_port"];
	        this.protocol = source["protocol"];
	        this.state = source["state"];
	        this.direction = source["direction"];
	        this.dns_name = source["dns_name"];
	        this.risk_level = source["risk_level"];
	        this.risk_reasons = source["risk_reasons"];
	        this.is_suspicious = source["is_suspicious"];
	        this.is_whitelisted = source["is_whitelisted"];
	    }
	}
	export class SecurityResp {
	    pid: number;
	    name: string;
	    exe_path: string;
	    priv_level: string;
	    is_signed: boolean;
	    is_elevated: boolean;
	    username: string;
	
	    static createFrom(source: any = {}) {
	        return new SecurityResp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pid = source["pid"];
	        this.name = source["name"];
	        this.exe_path = source["exe_path"];
	        this.priv_level = source["priv_level"];
	        this.is_signed = source["is_signed"];
	        this.is_elevated = source["is_elevated"];
	        this.username = source["username"];
	    }
	}
	export class SystemInfoResp {
	    hostname: string;
	    os_platform: string;
	    local_ips: string[];
	
	    static createFrom(source: any = {}) {
	        return new SystemInfoResp(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hostname = source["hostname"];
	        this.os_platform = source["os_platform"];
	        this.local_ips = source["local_ips"];
	    }
	}
	export class ScanResult {
	    system?: SystemInfoResp;
	    connections: ConnectionResp[];
	    processes: ProcessResp[];
	    risks: RiskResp[];
	    security: SecurityResp[];
	    baseline?: BaselineResp;
	    findings?: FindingsResp;
	    dns_queries?: DNSQueriesResp;
	    scan_time: string;
	    dns_lookups: number;
	
	    static createFrom(source: any = {}) {
	        return new ScanResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.system = this.convertValues(source["system"], SystemInfoResp);
	        this.connections = this.convertValues(source["connections"], ConnectionResp);
	        this.processes = this.convertValues(source["processes"], ProcessResp);
	        this.risks = this.convertValues(source["risks"], RiskResp);
	        this.security = this.convertValues(source["security"], SecurityResp);
	        this.baseline = this.convertValues(source["baseline"], BaselineResp);
	        this.findings = this.convertValues(source["findings"], FindingsResp);
	        this.dns_queries = this.convertValues(source["dns_queries"], DNSQueriesResp);
	        this.scan_time = source["scan_time"];
	        this.dns_lookups = source["dns_lookups"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class SnapshotResponse {
	    name: string;
	    timestamp: string;
	    snapshot_path: string;
	
	    static createFrom(source: any = {}) {
	        return new SnapshotResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.timestamp = source["timestamp"];
	        this.snapshot_path = source["snapshot_path"];
	    }
	}
	
	
	

}

