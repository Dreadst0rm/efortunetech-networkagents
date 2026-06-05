package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"networksentinel/scanner"
)

var dnsResolver = &net.Resolver{}

// dnsResult holds the result of a single reverse DNS lookup.
type dnsResult struct {
	idx  int
	addr string
	name string
	err  error
}

// LookupDomain performs a reverse DNS lookup on an IP address and returns the resolved domain name.
// Returns empty string if no reverse DNS record exists or lookup fails.
func LookupDomain(addr string) string {
	if addr == "" || addr == "0.0.0.0" || addr == "*" {
		return ""
	}

	// Strip brackets for IPv6
	clean := addr
	if strings.HasPrefix(clean, "[") {
		idx := strings.Index(clean, "]")
		if idx > 0 {
			clean = clean[1:idx]
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := dnsResolver.LookupAddr(ctx, clean)
	if err != nil || len(names) == 0 {
		return ""
	}

	// Return the first non-empty result, stripped of trailing dot
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name != "" {
			return name
		}
	}

	return ""
}

// LookupResult holds a single resolved domain name for an IP address.
type LookupResult struct {
	Addr string // original IP address
	Name string // resolved domain name
}

// LookupDomainsParallel performs concurrent reverse DNS lookups for a slice of IP addresses.
// It uses a worker pool limited by concurrency to avoid overwhelming DNS servers.
// Each lookup has a 2-second timeout. Results are returned in the same order as input.
// Non-outbound and empty addresses are skipped and returned with empty Name.
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
			// Already resolved (e.g., from prior lookup).
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

	// Worker pool: channels for tasks and results.
	type task struct {
		idx  int
		addr string
	}
	tasks := make(chan task, len(uniqueAddrs))
	resultsCh := make(chan dnsResult, len(uniqueAddrs))

	// Launch workers.
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				name, err := resolveAddr(t.addr)
				resultsCh <- dnsResult{addr: t.addr, name: name, err: err}
			}
		}()
	}

	// Send tasks.
	for _, a := range uniqueAddrs {
		tasks <- task{idx: seen[a], addr: a}
	}
	close(tasks)

	// Drain results.
	wg.Wait()
	close(resultsCh)

	for r := range resultsCh {
		results[r.idx].Name = r.name
	}

	return results
}

// resolveAddr performs a single reverse DNS lookup with timeout.
func resolveAddr(addr string) (string, error) {
	if addr == "" || addr == "0.0.0.0" || addr == "*" {
		return "", nil
	}

	clean := addr
	if strings.HasPrefix(clean, "[") {
		idx := strings.Index(clean, "]")
		if idx > 0 {
			clean = clean[1:idx]
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := dnsResolver.LookupAddr(ctx, clean)
	if err != nil {
		return "", err
	}

	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name != "" {
			return name, nil
		}
	}

	return "", nil
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

	if len(tasks) == 0 {
		return 0
	}

	addrs := make([]string, len(tasks))
	for i, t := range tasks {
		addrs[i] = t.addr
	}

	results := LookupDomainsParallel(addrs, concurrency)

	count := 0
	for i, r := range results {
		if r.Name == "" {
			continue
		}
		t := tasks[i]
		conns[t.connIdx].DNSName = r.Name
		count++
	}

	return count
}

// DNSQueriesToIPMap builds a map from IP address to the first domain name
// that resolved to it from the given DNS queries.
func DNSQueriesToIPMap(queries []Query) map[string]string {
	ipMap := make(map[string]string)
	for _, q := range queries {
		if q.QueryName == "" {
			continue
		}
		if ip := ResolveDomainToIP(q.QueryName); ip != "" {
			if _, exists := ipMap[ip]; !exists {
				ipMap[ip] = q.QueryName
			}
		}
	}
	return ipMap
}

// ResolveDomainToIP performs a forward DNS lookup and returns the first IPv4 address.
func ResolveDomainToIP(domain string) string {
	if domain == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := dnsResolver.LookupIPAddr(ctx, domain)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return ip.IP.String()
		}
	}
	return ""
}
