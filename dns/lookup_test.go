package dns

import (
	"testing"
)

// BenchmarkCheckDomain measures DNS domain suspicion analysis.
func BenchmarkCheckDomain(b *testing.B) {
	domains := []string{
		"google.com",
		"secure-login-verify.tk",
		"account-verify-secure.xyz",
		"portal-auth-verify.top",
		"a.b.c.d.e.f.g.example.com",
		"this-is-a-very-long-domain-name-that-exceeds-fifty-characters-and-should-be-flagged-as-suspicious.com",
	}

	for _, d := range domains {
		name := d
		b.Run("CheckDomain_"+name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				CheckDomain(name)
			}
		})
	}
}

func TestLookupDomain_IPv4(t *testing.T) {
	// Localhost reverse lookup should return something
	result := LookupDomain("127.0.0.1")
	t.Logf("LookupDomain(127.0.0.1) = %q", result)
}

func TestLookupDomain_Empty(t *testing.T) {
	result := LookupDomain("")
	if result != "" {
		t.Errorf("expected empty string for empty input, got %q", result)
	}
}

func TestLookupDomain_InvalidIP(t *testing.T) {
	result := LookupDomain("0.0.0.0")
	if result != "" {
		t.Errorf("expected empty string for 0.0.0.0, got %q", result)
	}
}

func TestLookupDomain_Wildcard(t *testing.T) {
	result := LookupDomain("*")
	if result != "" {
		t.Errorf("expected empty string for *, got %q", result)
	}
}

func TestLookupDomain_ExternalIP(t *testing.T) {
	// Try a real external IP — may or may not resolve, but should not panic
	result := LookupDomain("8.8.8.8")
	t.Logf("LookupDomain(8.8.8.8) = %q", result)
}

func TestLookupDomain_ReservedIP(t *testing.T) {
	// 0.0.0.0 should return empty
	result := LookupDomain("0.0.0.0")
	if result != "" {
		t.Errorf("expected empty for 0.0.0.0, got %q", result)
	}
}

// BenchmarkLookupDomainsParallel measures concurrent reverse DNS lookups.
func BenchmarkLookupDomainsParallel(b *testing.B) {
	addrs := []string{
		"8.8.8.8", "1.1.1.1", "1.0.0.1", "208.67.222.222",
		"208.67.220.220", "9.9.9.9", "149.112.112.112", "64.6.64.6",
		"192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1",
		"8.8.4.4", "13.107.42.14", "52.96.166.242", "151.101.1.69",
	}

	b.Run("16_addrs_concurrency_10", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			results := LookupDomainsParallel(addrs, 10)
			for _, r := range results {
				_ = r.Name
			}
		}
	})

	b.Run("16_addrs_concurrency_4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			results := LookupDomainsParallel(addrs, 4)
			for _, r := range results {
				_ = r.Name
			}
		}
	})

	b.Run("16_addrs_concurrency_1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			results := LookupDomainsParallel(addrs, 1)
			for _, r := range results {
				_ = r.Name
			}
		}
	})
}
