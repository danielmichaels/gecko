package assessor

import (
	"context"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
)

// fakeProber returns programmed probe results keyed by target host so the dangling
// assessor's HTTP path is exercised without real egress.
type fakeProber struct {
	results map[string]ProbeResult
}

func (f fakeProber) Probe(_ context.Context, target string) ProbeResult {
	if r, ok := f.results[strings.TrimSuffix(target, ".")]; ok {
		return r
	}
	return ProbeResult{Reached: false}
}

func danglingByTarget(
	findings []store.DanglingCnameFindings,
	target string,
) (store.DanglingCnameFindings, bool) {
	for _, f := range findings {
		if f.TargetDomain == target {
			return f, true
		}
	}
	return store.DanglingCnameFindings{}, false
}

func TestAssessCNAMEDangling(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

	mockServer, err := testhelpers.NewMockDNSServer()
	if err != nil {
		t.Fatalf("Failed to create mock DNS server: %v", err)
	}
	if err := mockServer.Start(); err != nil {
		t.Fatalf("Failed to start mock DNS server: %v", err)
	}
	defer func() { _ = mockServer.Stop() }()

	dnsClient := dnsclient.New(
		dnsclient.WithServers([]string{mockServer.ListenAddr}),
		dnsclient.WithLogger(testhelpers.TestLogger),
	)

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

	seedCNAME := func(t *testing.T, domainID int32, target string) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateCNAME(ctx, store.RecordsCreateCNAMEParams{
			DomainID: pgtype.Int4{Int32: domainID, Valid: true},
			Target:   target,
		}); err != nil {
			t.Fatalf("Failed to seed CNAME record: %v", err)
		}
	}

	assess := func(t *testing.T, d store.DomainsCreateRow, prober HTTPProber) []store.DanglingCnameFindings {
		t.Helper()
		ident := observer.DomainIdentity{
			TenantID:   1,
			DomainID:   d.ID,
			DomainUID:  d.Uid,
			DomainName: d.Name,
		}
		a := NewAssessor(Config{
			Store:      pgContainer.Queries,
			Logger:     testhelpers.TestLogger,
			DNSClient:  dnsClient,
			HTTPProber: prober,
			Identity:   ident,
		})
		if err := a.AssessCNAMEDangling(ctx, d.Uid); err != nil {
			t.Fatalf("AssessCNAMEDangling failed: %v", err)
		}
		findings, err := pgContainer.Queries.AssessGetDanglingCnameFindingsByDomainUID(
			ctx,
			store.AssessGetDanglingCnameFindingsByDomainUIDParams{
				Uid:      d.Uid,
				TenantID: pgtype.Int4{Int32: 1, Valid: true},
			},
		)
		if err != nil {
			t.Fatalf("Failed to get dangling CNAME findings: %v", err)
		}
		return findings
	}

	t.Run("non-resolving target without fingerprint is medium, not takeover", func(t *testing.T) {
		d := newDomain(t, "gone-target.test")
		target := "removed.internal.test"
		seedCNAME(t, d.ID, target)
		t.Cleanup(func() { mockServer.ClearRecords() })

		findings := assess(t, d, fakeProber{})
		f, ok := danglingByTarget(findings, target)
		if !ok {
			t.Fatalf("expected a dangling finding for %s", target)
		}
		if f.Severity != store.FindingSeverityMedium {
			t.Errorf("severity: got=%s want=medium", f.Severity)
		}
		if f.TakeoverPossible {
			t.Error("did not expect takeover_possible for a bare non-resolving target")
		}
	})

	t.Run("takeover provider with confirmed unclaimed page is high takeover", func(t *testing.T) {
		d := newDomain(t, "takeover.test")
		target := "victim-bucket.s3.amazonaws.com"
		seedCNAME(t, d.ID, target)
		if err := mockServer.AddRecord(target, dns.TypeA, 3600, "192.0.2.50"); err != nil {
			t.Fatalf("add A record: %v", err)
		}
		t.Cleanup(func() { mockServer.ClearRecords() })

		prober := fakeProber{results: map[string]ProbeResult{
			target: {
				Reached:    true,
				StatusCode: 404,
				Body:       "<Error><Code>NoSuchBucket</Code></Error>",
			},
		}}
		findings := assess(t, d, prober)
		f, ok := danglingByTarget(findings, target)
		if !ok {
			t.Fatalf("expected a dangling finding for %s", target)
		}
		if f.Severity != store.FindingSeverityHigh {
			t.Errorf("severity: got=%s want=high", f.Severity)
		}
		if !f.TakeoverPossible {
			t.Error("expected takeover_possible for a confirmed unclaimed bucket")
		}
		if f.ServiceProvider.String != "AWS S3" {
			t.Errorf("provider: got=%q want=AWS S3", f.ServiceProvider.String)
		}
	})

	t.Run("takeover provider serving a live page is suppressed", func(t *testing.T) {
		d := newDomain(t, "live-bucket.test")
		target := "live-bucket.s3.amazonaws.com"
		seedCNAME(t, d.ID, target)
		if err := mockServer.AddRecord(target, dns.TypeA, 3600, "192.0.2.60"); err != nil {
			t.Fatalf("add A record: %v", err)
		}
		t.Cleanup(func() { mockServer.ClearRecords() })

		prober := fakeProber{results: map[string]ProbeResult{
			target: {Reached: true, StatusCode: 200, Body: "<html>real site</html>"},
		}}
		findings := assess(t, d, prober)
		if _, ok := danglingByTarget(findings, target); ok {
			t.Error("expected a live takeover-provider page to be suppressed")
		}
	})

	t.Run("healthy resolving target without fingerprint yields no finding", func(t *testing.T) {
		d := newDomain(t, "healthy.test")
		target := "edge.example.test"
		seedCNAME(t, d.ID, target)
		if err := mockServer.AddRecord(target, dns.TypeA, 3600, "192.0.2.70"); err != nil {
			t.Fatalf("add A record: %v", err)
		}
		t.Cleanup(func() { mockServer.ClearRecords() })

		findings := assess(t, d, fakeProber{})
		if _, ok := danglingByTarget(findings, target); ok {
			t.Error("did not expect a finding for a healthy resolving target")
		}
	})

	t.Run("CNAME pointing to an IP yields a points_to_ip redirection finding", func(t *testing.T) {
		d := newDomain(t, "ip-target.test")
		target := "192.0.2.99"
		seedCNAME(t, d.ID, target)
		t.Cleanup(func() { mockServer.ClearRecords() })

		_ = assess(t, d, fakeProber{})
		redir, err := pgContainer.Queries.AssessGetCnameRedirectionFindingsByDomainUID(
			ctx,
			store.AssessGetCnameRedirectionFindingsByDomainUIDParams{
				Uid:      d.Uid,
				TenantID: pgtype.Int4{Int32: 1, Valid: true},
			},
		)
		if err != nil {
			t.Fatalf("get redirection findings: %v", err)
		}
		var found bool
		for _, f := range redir {
			if f.IssueType == IssuePointsToIP {
				found = true
			}
		}
		if !found {
			t.Error("expected a points_to_ip redirection finding")
		}
	})

	t.Run("zero identity still writes findings without emitting observations", func(t *testing.T) {
		d := newDomain(t, "no-identity.test")
		target := "orphan.internal.test"
		seedCNAME(t, d.ID, target)
		t.Cleanup(func() { mockServer.ClearRecords() })

		// TenantID set (so the tenant-scoped domain lookup succeeds) but DomainID
		// left zero, so Recordable() is false and observation emission is skipped.
		a := NewAssessor(Config{
			Store:     pgContainer.Queries,
			Logger:    testhelpers.TestLogger,
			DNSClient: dnsClient,
			Identity:  observer.DomainIdentity{TenantID: 1},
		})
		if err := a.AssessCNAMEDangling(ctx, d.Uid); err != nil {
			t.Fatalf("AssessCNAMEDangling failed: %v", err)
		}
		findings, err := pgContainer.Queries.AssessGetDanglingCnameFindingsByDomainUID(
			ctx,
			store.AssessGetDanglingCnameFindingsByDomainUIDParams{
				Uid:      d.Uid,
				TenantID: pgtype.Int4{Int32: 1, Valid: true},
			},
		)
		if err != nil {
			t.Fatalf("get findings: %v", err)
		}
		if _, ok := danglingByTarget(findings, target); !ok {
			t.Error("expected finding to be written even without a scan identity")
		}
	})
}
