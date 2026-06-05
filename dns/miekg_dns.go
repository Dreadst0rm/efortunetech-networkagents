package dns

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSSession represents an active DNS session for cache capture.
type DNSSession struct {
	client *dns.Client
	server string
}

// NewDNSSession creates a DNS session using Google DNS as the resolver.
func NewDNSSession() (*DNSSession, error) {
	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	return &DNSSession{
		client: client,
		server: "8.8.8.8:53",
	}, nil
}

// QueryDomain performs a forward DNS lookup using miekg/dns.
// Returns the resolved IPv4 addresses for the given domain.
func (s *DNSSession) QueryDomain(domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	r, _, err := s.client.Exchange(m, s.server)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}

	return ips, nil
}

// QueryDomainPTR performs a reverse DNS lookup using miekg/dns.
// Returns the pointer record (domain name) for the given IP.
func (s *DNSSession) QueryDomainPTR(ip string) (string, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid IPv4 address: %s", ip)
	}

	// Reverse the IP for PTR lookup
	reversed := []string{parts[3], parts[2], parts[1], parts[0]}
	ptr := strings.Join(reversed, ".") + ".in-addr.arpa."

	m := new(dns.Msg)
	m.SetQuestion(ptr, dns.TypePTR)

	r, _, err := s.client.Exchange(m, s.server)
	if err != nil {
		return "", err
	}

	for _, ans := range r.Answer {
		if ptrRec, ok := ans.(*dns.PTR); ok {
			name := strings.TrimSuffix(ptrRec.Ptr, ".")
			if name != "" {
				return name, nil
			}
		}
	}

	return "", nil
}

// QueryMultipleDomains performs concurrent DNS lookups for multiple domains.
// Returns a map from domain to first resolved IPv4 address.
func (s *DNSSession) QueryMultipleDomains(domains []string, concurrency int) map[string]string {
	if concurrency <= 0 {
		concurrency = 20
	}

	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, concurrency)
	for _, domain := range domains {
		sem <- struct{}{}
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()

			ips, err := s.QueryDomain(d)
			if err != nil || len(ips) == 0 {
				return
			}

			mu.Lock()
			results[d] = ips[0]
			mu.Unlock()
		}(domain)
	}

	wg.Wait()
	return results
}

// QueryMultiplePTRs performs concurrent reverse DNS lookups for multiple IPs.
// Returns a map from IP to resolved domain name.
func (s *DNSSession) QueryMultiplePTRs(ips []string, concurrency int) map[string]string {
	if concurrency <= 0 {
		concurrency = 20
	}

	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, concurrency)
	for _, ip := range ips {
		sem <- struct{}{}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()

			name, err := s.QueryDomainPTR(addr)
			if err != nil || name == "" {
				return
			}

			mu.Lock()
			results[addr] = name
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}
