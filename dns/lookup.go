package dns

import (
	"networksentinel/scanner"
)

// dnsSession is a shared DNS session using miekg/dns for all lookups.
var dnsSession *DNSSession

// init creates a shared DNS session for lookups.
func init() {
	s, err := NewDNSSession()
	if err != nil {
		dnsSession = nil
	} else {
		dnsSession = s
	}
}

// DNSCacheEntry represents a captured DNS cache entry with forward resolution.
type DNSCacheEntry struct {
	Domain string
	IP     string
	PID    int
}

// CollectDNSCacheEntries performs forward DNS lookups on a list of domains
// and returns the resolved IP addresses. This complements reverse DNS lookups
// by providing forward resolution data.
func CollectDNSCacheEntries(domains []string, concurrency int) []DNSCacheEntry {
	if len(domains) == 0 || dnsSession == nil {
		return nil
	}

	results := dnsSession.QueryMultipleDomains(domains, concurrency)
	entries := make([]DNSCacheEntry, 0, len(results))
	for domain, ip := range results {
		entries = append(entries, DNSCacheEntry{
			Domain: domain,
			IP:     ip,
			PID:    0,
		})
	}

	return entries
}

// LookupResult holds a single resolved domain name for an IP address.
type LookupResult struct {
	Addr string // original IP address
	Name string // resolved domain name
}

// LookupDomain performs a reverse DNS lookup on an IP address and returns the resolved domain name.
// Returns empty string if no reverse DNS record exists or lookup fails.
func LookupDomain(addr string) string {
	if addr == "" || addr == "0.0.0.0" || addr == "*" {
		return ""
	}

	if dnsSession == nil {
		return ""
	}

	name, err := dnsSession.QueryDomainPTR(addr)
	if err != nil || name == "" {
		return ""
	}

	return name
}

// LookupDomainsParallel performs concurrent reverse DNS lookups for a slice of IP addresses
// using miekg/dns. Results are returned in the same order as input.
func LookupDomainsParallel(addrs []string, concurrency int) []LookupResult {
	if concurrency <= 0 {
		concurrency = 10
	}

	// Pre-allocate result slice to preserve order.
	results := make([]LookupResult, len(addrs))
	for i, a := range addrs {
		results[i].Addr = a
	}

	// Deduplicate addresses to avoid redundant lookups.
	seen := make(map[string]int) // addr -> index in results
	var uniqueAddrs []string
	for i, a := range addrs {
		if results[i].Name != "" {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = i
		uniqueAddrs = append(uniqueAddrs, a)
	}

	if len(uniqueAddrs) == 0 {
		return results
	}

	if dnsSession == nil {
		return results
	}

	// Use miekg/dns session for parallel PTR lookups.
	ptrResults := dnsSession.QueryMultiplePTRs(uniqueAddrs, concurrency)

	for _, addr := range uniqueAddrs {
		if name, ok := ptrResults[addr]; ok {
			results[seen[addr]].Name = name
		}
	}

	return results
}

// ResolveConnectionsDNS performs parallel DNS lookups on outbound connections and
// populates c.DNSName for each connection that resolved.
// Returns the number of successfully resolved domains.
func ResolveConnectionsDNS(conns []scanner.Connection, concurrency int) int {
	// Collect unique outbound addresses.
	type addrIndex struct {
		connIdx int
		addr    string
	}
	var tasks []addrIndex
	seen := make(map[string]bool)

	for i := range conns {
		c := &conns[i]
		if c.Direction != "outbound" || c.RemoteAddr == "" {
			continue
		}
		if seen[c.RemoteAddr] {
			continue
		}
		seen[c.RemoteAddr] = true
		tasks = append(tasks, addrIndex{connIdx: i, addr: c.RemoteAddr})
	}

	if len(tasks) == 0 || dnsSession == nil {
		return 0
	}

	addrs := make([]string, len(tasks))
	for i, t := range tasks {
		addrs[i] = t.addr
	}

	// Use miekg/dns for parallel PTR lookups.
	ptrResults := dnsSession.QueryMultiplePTRs(addrs, concurrency)

	count := 0
	for i, addr := range addrs {
		if name, ok := ptrResults[addr]; ok && name != "" {
			t := tasks[i]
			conns[t.connIdx].DNSName = name
			count++
		}
	}

	return count
}

// DNSQueriesToIPMap builds a map from IP address to the first domain name
// that resolved to it from the given DNS queries using miekg/dns forward lookups.
func DNSQueriesToIPMap(queries []Query) map[string]string {
	if dnsSession == nil || len(queries) == 0 {
		return make(map[string]string)
	}

	domains := make([]string, 0, len(queries))
	for _, q := range queries {
		if q.QueryName != "" {
			domains = append(domains, q.QueryName)
		}
	}

	results := dnsSession.QueryMultipleDomains(domains, 20)
	ipMap := make(map[string]string)
	for domain, ip := range results {
		if _, exists := ipMap[ip]; !exists {
			ipMap[ip] = domain
		}
	}

	return ipMap
}

// ResolveDomainToIP performs a forward DNS lookup and returns the first IPv4 address
// using miekg/dns.
func ResolveDomainToIP(domain string) string {
	if domain == "" || dnsSession == nil {
		return ""
	}

	ips, err := dnsSession.QueryDomain(domain)
	if err != nil || len(ips) == 0 {
		return ""
	}

	return ips[0]
}
