package assessor

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
)

func TestAssessDanglingNS(t *testing.T) {
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
			t.Fatalf("create domain %s: %v", name, err)
		}
		return d
	}

	seedNS := func(t *testing.T, domainID int32, nameserver string) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateNS(ctx, store.RecordsCreateNSParams{
			DomainID:   pgtype.Int4{Int32: domainID, Valid: true},
			Nameserver: nameserver,
		}); err != nil {
			t.Fatalf("seed NS %s: %v", nameserver, err)
		}
	}

	seedSOA := func(t *testing.T, apex string) {
		t.Helper()
		rdata := "ns1." + apex + ". hostmaster." + apex + ". 1 3600 600 1209600 3600"
		if err := mockServer.AddRecord(apex, dns.TypeSOA, 3600, rdata); err != nil {
			t.Fatalf("seed SOA %s: %v", apex, err)
		}
	}

	run := func(t *testing.T, d store.DomainsCreateRow) {
		t.Helper()
		a := NewAssessor(Config{
			Store:     pgContainer.Queries,
			Logger:    testhelpers.TestLogger,
			DNSClient: dnsClient,
			Identity: observer.DomainIdentity{
				TenantID:   1,
				DomainID:   d.ID,
				DomainUID:  d.Uid,
				DomainName: d.Name,
			},
		})
		if err := a.AssessDanglingNS(ctx, d.Uid); err != nil {
			t.Fatalf("AssessDanglingNS: %v", err)
		}
	}

	getConfig := func(t *testing.T, d store.DomainsCreateRow) []store.NsConfigurationFindings {
		t.Helper()
		fs, err := pgContainer.Queries.AssessGetNSConfigurationFindingsByDomainUID(ctx,
			store.AssessGetNSConfigurationFindingsByDomainUIDParams{
				Uid: d.Uid, TenantID: pgtype.Int4{Int32: 1, Valid: true},
			})
		if err != nil {
			t.Fatalf("get ns config findings: %v", err)
		}
		return fs
	}

	t.Run("an NS in a non-existent parent domain is a dangling delegation", func(t *testing.T) {
		d := newDomain(t, "victim.test")
		seedNS(t, d.ID, "ns1.abandoned-zone.test") // apex abandoned-zone.test has no SOA → NXDOMAIN
		run(t, d)

		f, ok := nsConfigByIssue(getConfig(t, d), "ns1.abandoned-zone.test", DanglingNS)
		if !ok {
			t.Fatalf("expected dangling_ns finding")
		}
		if f.Severity != store.FindingSeverityHigh || f.Status != store.FindingStatusOpen {
			t.Errorf("expected high/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("an NS in a registered parent domain is resolved", func(t *testing.T) {
		d := newDomain(t, "healthy.test")
		seedNS(t, d.ID, "ns1.live-zone.test")
		seedSOA(t, "live-zone.test")
		run(t, d)

		f, ok := nsConfigByIssue(getConfig(t, d), "ns1.live-zone.test", DanglingNS)
		if !ok {
			t.Fatalf("expected a dangling_ns row (resolved)")
		}
		if f.Status != store.FindingStatusResolved {
			t.Errorf("expected resolved, got %s", f.Status)
		}
	})

	t.Run("an in-bailiwick NS is skipped", func(t *testing.T) {
		d := newDomain(t, "inhouse.test")
		seedNS(t, d.ID, "ns1.inhouse.test") // apex == domain apex → skipped, no query
		run(t, d)

		if _, ok := nsConfigByIssue(getConfig(t, d), "ns1.inhouse.test", DanglingNS); ok {
			t.Error("did not expect a dangling_ns finding for an in-bailiwick nameserver")
		}
	})

	t.Run("re-running does not duplicate findings", func(t *testing.T) {
		d := newDomain(t, "idempotent-dangling.test")
		seedNS(t, d.ID, "ns1.gone-zone.test")
		run(t, d)
		run(t, d)

		var count int
		for _, f := range getConfig(t, d) {
			if f.Nameserver == "ns1.gone-zone.test" && f.IssueType == DanglingNS {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected exactly one dangling_ns finding after re-run, got %d", count)
		}
	})
}
