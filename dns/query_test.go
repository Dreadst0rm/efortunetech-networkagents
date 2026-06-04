package dns

import (
	"strings"
	"testing"
)

func TestCheckDomain_SuspiciousTLD(t *testing.T) {
	result := CheckDomain("evil.tk")
	if !result.IsSuspicious {
		t.Errorf("expected suspicious for .tk TLD, got not suspicious")
	}
	if result.Confidence < 0.5 {
		t.Errorf("expected confidence >= 0.5, got %.2f", result.Confidence)
	}
}

func TestCheckDomain_NormalDomain(t *testing.T) {
	result := CheckDomain("google.com")
	if result.IsSuspicious {
		t.Errorf("expected not suspicious for google.com, got suspicious")
	}
}

func TestCheckDomain_DGALike(t *testing.T) {
	result := CheckDomain("abcdefghijklmnopqrstuvwxyz1234567890abcdef.malware.top")
	if !result.IsSuspicious {
		t.Errorf("expected suspicious for DGA-like domain, got not suspicious")
	}
}

func TestCheckDomain_EmptyDomain(t *testing.T) {
	result := CheckDomain("")
	if result.Confidence != 0 {
		t.Errorf("expected 0 confidence for empty domain, got %.2f", result.Confidence)
	}
}

func TestCheckDomain_LongDomain(t *testing.T) {
	domain := "a" + strings.Repeat("a", 60) + ".top"
	result := CheckDomain(domain)
	if !result.IsSuspicious {
		t.Errorf("expected suspicious for long domain with suspicious TLD, got not suspicious")
	}
}

func TestCheckDomain_SubdomainDepth(t *testing.T) {
	result := CheckDomain("a.b.c.d.e.example.tk")
	if !result.IsSuspicious {
		t.Errorf("expected suspicious for high depth domain with suspicious TLD, got not suspicious")
	}
}

func TestCheckDomain_ConsonantRatio(t *testing.T) {
	result := CheckDomain("bxzqkvwrtmn.com")
	if result.Confidence == 0 {
		t.Errorf("expected non-zero confidence for high consonant ratio, got 0")
	}
}

func TestCheckDomain_Keywords(t *testing.T) {
	result := CheckDomain("secure-login-portal.evil.xyz")
	if !result.IsSuspicious {
		t.Errorf("expected suspicious for domain with keyword and suspicious TLD, got not suspicious")
	}
}

func TestQueryLog_AddAndGet(t *testing.T) {
	log := NewQueryLog()
	log.AddRecord(Query{QueryName: "test.com", PID: 1234})
	queries := log.GetQueries()
	if len(queries) != 1 {
		t.Errorf("expected 1 query, got %d", len(queries))
	}
	if queries[0].PID != 1234 {
		t.Errorf("expected PID 1234, got %d", queries[0].PID)
	}
}

func TestQueryLog_Clear(t *testing.T) {
	log := NewQueryLog()
	log.AddRecord(Query{QueryName: "test.com"})
	log.Clear()
	if len(log.GetQueries()) != 0 {
		t.Errorf("expected 0 queries after clear, got %d", len(log.GetQueries()))
	}
}

func TestCheckDomain_KeywordOnly(t *testing.T) {
	result := CheckDomain("login-portal.example.com")
	if result.Confidence == 0 {
		t.Errorf("expected non-zero confidence for keyword domain, got 0")
	}
}
