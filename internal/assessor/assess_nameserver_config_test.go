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

func nsConfigByIssue(
	findings []store.NsConfigurationFindings,
	nameserver, issueType string,
) (store.NsConfigurationFindings, bool) {
	for _, f := range findings {
		if f.Nameserver == nameserver && f.IssueType == issueType {
			return f, true
		}
	}
	return store.NsConfigurationFindings{}, false
}

func nsRedundancyByIssue(
	findings []store.NameserverRedundancyFindings,
	issueType string,
) (store.NameserverRedundancyFindings, bool) {
	for _, f := range findings {
		if f.IssueType == issueType {
			return f, true
		}
	}
	return store.NameserverRedundancyFindings{}, false
}

func TestAssessNameserverConfig(t *testing.T) {
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

	seedNS := func(t *testing.T, domainID int32, nameserver string) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateNS(ctx, store.RecordsCreateNSParams{
			DomainID:   pgtype.Int4{Int32: domainID, Valid: true},
			Nameserver: nameserver,
		}); err != nil {
			t.Fatalf("Failed to seed NS record %s: %v", nameserver, err)
		}
	}

	addAddr := func(t *testing.T, host string, rrtype uint16, value string) {
		t.Helper()
		if err := mockServer.AddRecord(host, rrtype, 3600, value); err != nil {
			t.Fatalf("Failed to add %s record for %s: %v", value, host, err)
		}
	}

	run := func(t *testing.T, d store.DomainsCreateRow) {
		t.Helper()
		ident := observer.DomainIdentity{
			TenantID:   1,
			DomainID:   d.ID,
			DomainUID:  d.Uid,
			DomainName: d.Name,
		}
		a := NewAssessor(Config{
			Store:     pgContainer.Queries,
			Logger:    testhelpers.TestLogger,
			DNSClient: dnsClient,
			Identity:  ident,
		})
		if err := a.AssessNameserverConfig(ctx, d.Uid); err != nil {
			t.Fatalf("AssessNameserverConfig failed: %v", err)
		}
	}

	getConfig := func(t *testing.T, d store.DomainsCreateRow) []store.NsConfigurationFindings {
		t.Helper()
		findings, err := pgContainer.Queries.AssessGetNSConfigurationFindingsByDomainUID(
			ctx,
			store.AssessGetNSConfigurationFindingsByDomainUIDParams{
				Uid:      d.Uid,
				TenantID: pgtype.Int4{Int32: 1, Valid: true},
			},
		)
		if err != nil {
			t.Fatalf("Failed to get NS configuration findings: %v", err)
		}
		return findings
	}

	getRedundancy := func(t *testing.T, d store.DomainsCreateRow) []store.NameserverRedundancyFindings {
		t.Helper()
		findings, err := pgContainer.Queries.AssessGetNameserverRedundancyFindingsByDomainUID(
			ctx,
			store.AssessGetNameserverRedundancyFindingsByDomainUIDParams{
				Uid:      d.Uid,
				TenantID: pgtype.Int4{Int32: 1, Valid: true},
			},
		)
		if err != nil {
			t.Fatalf("Failed to get nameserver redundancy findings: %v", err)
		}
		return findings
	}

	t.Run("a single nameserver is a high-severity redundancy gap", func(t *testing.T) {
		d := newDomain(t, "solo-ns.test")
		ns := "ns1.solo-provider.com"
		seedNS(t, d.ID, ns)
		addAddr(t, ns, dns.TypeA, "192.0.2.10")
		addAddr(t, ns, dns.TypeAAAA, "2001:db8::10")
		run(t, d)

		f, ok := nsRedundancyByIssue(getRedundancy(t, d), NSInsufficientNameservers)
		if !ok {
			t.Fatalf("expected insufficient_nameservers finding")
		}
		if f.Severity != store.FindingSeverityHigh || f.Status != store.FindingStatusOpen {
			t.Errorf("expected high/open, got %s/%s", f.Severity, f.Status)
		}
		if f.NameserverCount != 1 || f.RecommendedCount != 2 {
			t.Errorf(
				"expected count 1 / recommended 2, got %d/%d",
				f.NameserverCount,
				f.RecommendedCount,
			)
		}
	})

	t.Run(
		"two nameservers at one provider is a medium single-provider finding",
		func(t *testing.T) {
			d := newDomain(t, "single-provider.test")
			ns1, ns2 := "ns1.oneprovider.com", "ns2.oneprovider.com"
			seedNS(t, d.ID, ns1)
			seedNS(t, d.ID, ns2)
			for _, ns := range []string{ns1, ns2} {
				addAddr(t, ns, dns.TypeA, "192.0.2.20")
				addAddr(t, ns, dns.TypeAAAA, "2001:db8::20")
			}
			run(t, d)

			red := getRedundancy(t, d)
			sp, ok := nsRedundancyByIssue(red, NSSameProvider)
			if !ok {
				t.Fatalf("expected same_provider finding")
			}
			if sp.Severity != store.FindingSeverityMedium || sp.Status != store.FindingStatusOpen {
				t.Errorf("expected medium/open, got %s/%s", sp.Severity, sp.Status)
			}
			if insuff, ok := nsRedundancyByIssue(red, NSInsufficientNameservers); ok {
				if insuff.Status != store.FindingStatusResolved {
					t.Errorf("expected insufficient_nameservers resolved, got %s", insuff.Status)
				}
			}
		},
	)

	t.Run("two diverse healthy nameservers produce no open findings", func(t *testing.T) {
		d := newDomain(t, "healthy-ns.test")
		ns1, ns2 := "ns1.alpha-dns.com", "ns2.beta-dns.net"
		seedNS(t, d.ID, ns1)
		seedNS(t, d.ID, ns2)
		addAddr(t, ns1, dns.TypeA, "192.0.2.31")
		addAddr(t, ns1, dns.TypeAAAA, "2001:db8::31")
		addAddr(t, ns2, dns.TypeA, "192.0.2.32")
		addAddr(t, ns2, dns.TypeAAAA, "2001:db8::32")
		run(t, d)

		for _, f := range getRedundancy(t, d) {
			if f.Status == store.FindingStatusOpen {
				t.Errorf("unexpected open redundancy finding %s", f.IssueType)
			}
		}
		for _, f := range getConfig(t, d) {
			if f.Status == store.FindingStatusOpen {
				t.Errorf("unexpected open config finding %s/%s", f.Nameserver, f.IssueType)
			}
		}
	})

	t.Run("a nameserver with no address is flagged not-resolvable", func(t *testing.T) {
		d := newDomain(t, "lame-ns.test")
		ns1, ns2 := "ns1.resolvable-dns.com", "ns2.broken-dns.net"
		seedNS(t, d.ID, ns1)
		seedNS(t, d.ID, ns2)
		addAddr(t, ns1, dns.TypeA, "192.0.2.41")
		addAddr(t, ns1, dns.TypeAAAA, "2001:db8::41")
		// ns2 deliberately has no A/AAAA/CNAME records.
		run(t, d)

		f, ok := nsConfigByIssue(getConfig(t, d), ns2, NSNotResolvable)
		if !ok {
			t.Fatalf("expected ns_not_resolvable finding for %s", ns2)
		}
		if f.Severity != store.FindingSeverityMedium || f.Status != store.FindingStatusOpen {
			t.Errorf("expected medium/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("a nameserver that is a CNAME is illegal", func(t *testing.T) {
		d := newDomain(t, "cname-ns.test")
		ns1, ns2 := "ns1.proper-dns.com", "ns2.aliased-dns.org"
		seedNS(t, d.ID, ns1)
		seedNS(t, d.ID, ns2)
		addAddr(t, ns1, dns.TypeA, "192.0.2.51")
		addAddr(t, ns1, dns.TypeAAAA, "2001:db8::51")
		addAddr(t, ns2, dns.TypeCNAME, "real-host.example.com")
		run(t, d)

		cfg := getConfig(t, d)
		f, ok := nsConfigByIssue(cfg, ns2, NSIsCNAME)
		if !ok {
			t.Fatalf("expected ns_is_cname finding for %s", ns2)
		}
		if f.Severity != store.FindingSeverityMedium || f.Status != store.FindingStatusOpen {
			t.Errorf("expected medium/open, got %s/%s", f.Severity, f.Status)
		}
		if nr, ok := nsConfigByIssue(cfg, ns2, NSNotResolvable); ok {
			if nr.Status != store.FindingStatusResolved {
				t.Errorf(
					"a CNAME nameserver should not be flagged not-resolvable, got %s",
					nr.Status,
				)
			}
		}
	})

	t.Run("a nameserver set without IPv6 is a low redundancy finding", func(t *testing.T) {
		d := newDomain(t, "no-ipv6-ns.test")
		ns1, ns2 := "ns1.ipv4only-dns.com", "ns2.ipv4only-dns.net"
		seedNS(t, d.ID, ns1)
		seedNS(t, d.ID, ns2)
		addAddr(t, ns1, dns.TypeA, "192.0.2.61")
		addAddr(t, ns2, dns.TypeA, "192.0.2.62")
		run(t, d)

		f, ok := nsRedundancyByIssue(getRedundancy(t, d), NSNoIPv6)
		if !ok {
			t.Fatalf("expected no_ipv6 finding")
		}
		if f.Severity != store.FindingSeverityLow || f.Status != store.FindingStatusOpen {
			t.Errorf("expected low/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("re-running does not duplicate findings", func(t *testing.T) {
		d := newDomain(t, "idempotent-ns.test")
		ns := "ns1.idem-provider.com"
		seedNS(t, d.ID, ns)
		addAddr(t, ns, dns.TypeA, "192.0.2.71")
		run(t, d)
		run(t, d)

		var count int
		for _, f := range getRedundancy(t, d) {
			if f.IssueType == NSInsufficientNameservers {
				count++
			}
		}
		if count != 1 {
			t.Errorf(
				"expected exactly one insufficient_nameservers finding after re-run, got %d",
				count,
			)
		}
	})
}
