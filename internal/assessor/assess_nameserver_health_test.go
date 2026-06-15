package assessor

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

// fakeNSProber returns canned probe results keyed by server address ("host:53"),
// so the nameserver-health assessor can be exercised without any network.
type fakeNSProber struct {
	results map[string]dnsclient.NSProbeResult
}

func (f *fakeNSProber) ProbeNameserver(
	server, name string,
	qtype uint16,
) dnsclient.NSProbeResult {
	return f.results[server]
}

func TestAssessNameserverHealth(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

	prober := &fakeNSProber{results: map[string]dnsclient.NSProbeResult{}}

	newDomain := func(t *testing.T, name string) store.DomainsCreateRow {
		t.Helper()
		d, err := pgContainer.Queries.DomainsCreate(ctx, store.DomainsCreateParams{
			TenantID:   pgtype.Int4{Int32: 1, Valid: true},
			Name:       name,
			DomainType: store.DomainTypeTld,
			Source:     store.DomainSourceUserSupplied,
			Status:     store.DomainStatusActive,
		})
		if err != nil {
			t.Fatalf("Failed to create domain %s: %v", name, err)
		}
		return d
	}

	seedNS := func(t *testing.T, domainID int32, nameserver string, probe dnsclient.NSProbeResult) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateNS(ctx, store.RecordsCreateNSParams{
			DomainID:   pgtype.Int4{Int32: domainID, Valid: true},
			Nameserver: nameserver,
		}); err != nil {
			t.Fatalf("Failed to seed NS record %s: %v", nameserver, err)
		}
		prober.results[net.JoinHostPort(nameserver, "53")] = probe
	}

	run := func(t *testing.T, d store.DomainsCreateRow) {
		t.Helper()
		a := NewAssessor(Config{
			Store:    pgContainer.Queries,
			Logger:   testhelpers.TestLogger,
			NSProber: prober,
			Identity: observer.DomainIdentity{
				TenantID:   1,
				DomainID:   d.ID,
				DomainUID:  d.Uid,
				DomainName: d.Name,
			},
		})
		if err := a.AssessNameserverHealth(ctx, d.Uid); err != nil {
			t.Fatalf("AssessNameserverHealth failed: %v", err)
		}
	}

	getReach := func(t *testing.T, d store.DomainsCreateRow) []store.NameserverReachabilityFindings {
		t.Helper()
		f, err := pgContainer.Queries.AssessGetNameserverReachabilityFindingsByDomainUID(ctx,
			store.AssessGetNameserverReachabilityFindingsByDomainUIDParams{
				Uid: d.Uid, TenantID: pgtype.Int4{Int32: 1, Valid: true},
			})
		if err != nil {
			t.Fatalf("get reachability: %v", err)
		}
		return f
	}
	getLatency := func(t *testing.T, d store.DomainsCreateRow) []store.DnsResolutionLatencyFindings {
		t.Helper()
		f, err := pgContainer.Queries.AssessGetDNSResolutionLatencyFindingsByDomainUID(ctx,
			store.AssessGetDNSResolutionLatencyFindingsByDomainUIDParams{
				Uid: d.Uid, TenantID: pgtype.Int4{Int32: 1, Valid: true},
			})
		if err != nil {
			t.Fatalf("get latency: %v", err)
		}
		return f
	}
	getConsistency := func(t *testing.T, d store.DomainsCreateRow) []store.DnsResolutionConsistencyFindings {
		t.Helper()
		f, err := pgContainer.Queries.AssessGetDNSResolutionConsistencyFindingsByDomainUID(ctx,
			store.AssessGetDNSResolutionConsistencyFindingsByDomainUIDParams{
				Uid: d.Uid, TenantID: pgtype.Int4{Int32: 1, Valid: true},
			})
		if err != nil {
			t.Fatalf("get consistency: %v", err)
		}
		return f
	}

	reachByIssue := func(fs []store.NameserverReachabilityFindings, ns, issue string) (store.NameserverReachabilityFindings, bool) {
		for _, f := range fs {
			if f.Nameserver == ns && f.IssueType == issue {
				return f, true
			}
		}
		return store.NameserverReachabilityFindings{}, false
	}
	latByResolver := func(fs []store.DnsResolutionLatencyFindings, ns string) (store.DnsResolutionLatencyFindings, bool) {
		for _, f := range fs {
			if f.Resolver == ns {
				return f, true
			}
		}
		return store.DnsResolutionLatencyFindings{}, false
	}

	healthy := dnsclient.NSProbeResult{
		Reachable: true, TCPOK: true, HasEDNS: true,
		RTT: 50 * time.Millisecond, Answers: []string{"soa-serial-100"},
	}

	t.Run("an unreachable nameserver is a high finding", func(t *testing.T) {
		d := newDomain(t, "unreachable-ns.test")
		seedNS(t, d.ID, "ns1.up-host.com", healthy)
		seedNS(t, d.ID, "ns2.down-host.com", dnsclient.NSProbeResult{Reachable: false})
		run(t, d)

		f, ok := reachByIssue(getReach(t, d), "ns2.down-host.com", NSUnreachable)
		if !ok {
			t.Fatalf("expected unreachable finding for ns2")
		}
		if f.Severity != store.FindingSeverityHigh || f.Status != store.FindingStatusOpen {
			t.Errorf("expected high/open, got %s/%s", f.Severity, f.Status)
		}
		if up, ok := reachByIssue(getReach(t, d), "ns1.up-host.com", NSUnreachable); ok {
			if up.Status != store.FindingStatusResolved {
				t.Errorf("expected reachable ns1 unreachable=resolved, got %s", up.Status)
			}
		}
	})

	t.Run("a reachable nameserver without TCP is a medium finding", func(t *testing.T) {
		d := newDomain(t, "notcp-ns.test")
		probe := healthy
		probe.TCPOK = false
		seedNS(t, d.ID, "ns1.notcp-host.com", probe)
		run(t, d)

		f, ok := reachByIssue(getReach(t, d), "ns1.notcp-host.com", NSNoTCPSupport)
		if !ok {
			t.Fatalf("expected no_tcp_support finding")
		}
		if f.Severity != store.FindingSeverityMedium || f.Status != store.FindingStatusOpen {
			t.Errorf("expected medium/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("a reachable nameserver without EDNS is an info finding", func(t *testing.T) {
		d := newDomain(t, "noedns-ns.test")
		probe := healthy
		probe.HasEDNS = false
		seedNS(t, d.ID, "ns1.noedns-host.com", probe)
		run(t, d)

		f, ok := reachByIssue(getReach(t, d), "ns1.noedns-host.com", NSNoEDNSSupport)
		if !ok {
			t.Fatalf("expected no_edns_support finding")
		}
		if f.Severity != store.FindingSeverityInfo || f.Status != store.FindingStatusOpen {
			t.Errorf("expected info/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("a slow nameserver is tiered by latency", func(t *testing.T) {
		d := newDomain(t, "slow-ns.test")
		probe := healthy
		probe.RTT = 500 * time.Millisecond
		seedNS(t, d.ID, "ns1.slow-host.com", probe)
		run(t, d)

		f, ok := latByResolver(getLatency(t, d), "ns1.slow-host.com")
		if !ok {
			t.Fatalf("expected latency finding")
		}
		if f.Severity != store.FindingSeverityLow || f.Status != store.FindingStatusOpen {
			t.Errorf("expected low/open, got %s/%s", f.Severity, f.Status)
		}
		if f.ThresholdMs != 400 || f.LatencyMs != 500 {
			t.Errorf("expected threshold 400 / latency 500, got %d/%d", f.ThresholdMs, f.LatencyMs)
		}
	})

	t.Run("a fast nameserver records latency as resolved", func(t *testing.T) {
		d := newDomain(t, "fast-ns.test")
		seedNS(t, d.ID, "ns1.fast-host.com", healthy)
		run(t, d)

		f, ok := latByResolver(getLatency(t, d), "ns1.fast-host.com")
		if !ok {
			t.Fatalf("expected latency finding")
		}
		if f.Status != store.FindingStatusResolved {
			t.Errorf("expected resolved, got %s", f.Status)
		}
	})

	t.Run("divergent SOA serials across nameservers flag consistency", func(t *testing.T) {
		d := newDomain(t, "divergent-ns.test")
		p1 := healthy
		p1.Answers = []string{"soa-serial-100"}
		p2 := healthy
		p2.Answers = []string{"soa-serial-200"}
		seedNS(t, d.ID, "ns1.consistent-a.com", p1)
		seedNS(t, d.ID, "ns2.consistent-b.com", p2)
		run(t, d)

		fs := getConsistency(t, d)
		if len(fs) == 0 {
			t.Fatalf("expected a consistency finding")
		}
		if fs[0].Severity != store.FindingSeverityLow || fs[0].Status != store.FindingStatusOpen {
			t.Errorf("expected low/open, got %s/%s", fs[0].Severity, fs[0].Status)
		}
	})

	t.Run("matching SOA serials record consistency as resolved", func(t *testing.T) {
		d := newDomain(t, "consistent-ns.test")
		seedNS(t, d.ID, "ns1.agree-a.com", healthy)
		seedNS(t, d.ID, "ns2.agree-b.com", healthy)
		run(t, d)

		for _, f := range getConsistency(t, d) {
			if f.Status == store.FindingStatusOpen {
				t.Errorf("expected no open consistency finding, got open %s", f.RecordType)
			}
		}
	})

	t.Run("re-running does not duplicate findings", func(t *testing.T) {
		d := newDomain(t, "idempotent-health.test")
		seedNS(t, d.ID, "ns1.idem-host.com", dnsclient.NSProbeResult{Reachable: false})
		run(t, d)
		run(t, d)

		var count int
		for _, f := range getReach(t, d) {
			if f.Nameserver == "ns1.idem-host.com" && f.IssueType == NSUnreachable {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected exactly one unreachable finding after re-run, got %d", count)
		}
	})
}
