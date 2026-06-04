package dns

import (
	"context"
	"net"
	"strings"
	"time"
)

var dnsResolver = &net.Resolver{}

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
			clean = clean[1 : idx]
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
