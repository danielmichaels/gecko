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

func minRecordFindingByIssueType(
	findings []store.MinimumRecordSetFindings,
	issueType string,
) (store.MinimumRecordSetFindings, bool) {
	for _, f := range findings {
		if f.IssueType == issueType {
			return f, true
		}
	}
	return store.MinimumRecordSetFindings{}, false
}

func TestAssessMinimumRecordSet(t *testing.T) {
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

	newDomain := func(t *testing.T, name string, dtype store.DomainType) store.DomainsCreateRow {
		t.Helper()
		d, err := pgContainer.Queries.DomainsCreate(ctx, store.DomainsCreateParams{
			TenantID:   pgtype.Int4{Int32: 1, Valid: true},
			Name:       name,
			DomainType: dtype,
			Source:     store.DomainSourceUserSupplied,
			Status:     store.DomainStatusActive,
		})
		if err != nil {
			t.Fatalf("Failed to create domain %s: %v", name, err)
		}
		return d
	}

	seedA := func(t *testing.T, domainID int32, ip string) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateA(ctx, store.RecordsCreateAParams{
			DomainID: pgtype.Int4{Int32: domainID, Valid: true}, Ipv4Address: ip,
		}); err != nil {
			t.Fatalf("seed A: %v", err)
		}
	}
	seedAAAA := func(t *testing.T, domainID int32, ip string) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateAAAA(ctx, store.RecordsCreateAAAAParams{
			DomainID: pgtype.Int4{Int32: domainID, Valid: true}, Ipv6Address: ip,
		}); err != nil {
			t.Fatalf("seed AAAA: %v", err)
		}
	}
	seedNS := func(t *testing.T, domainID int32, ns string) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateNS(ctx, store.RecordsCreateNSParams{
			DomainID: pgtype.Int4{Int32: domainID, Valid: true}, Nameserver: ns,
		}); err != nil {
			t.Fatalf("seed NS: %v", err)
		}
	}
	seedMX := func(t *testing.T, domainID int32, pref int32, target string) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateMX(ctx, store.RecordsCreateMXParams{
			DomainID: pgtype.Int4{Int32: domainID, Valid: true}, Preference: pref, Target: target,
		}); err != nil {
			t.Fatalf("seed MX: %v", err)
		}
	}
	seedTXT := func(t *testing.T, domainID int32, value string) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateTXT(ctx, store.RecordsCreateTXTParams{
			DomainID: pgtype.Int4{Int32: domainID, Valid: true}, Value: value,
		}); err != nil {
			t.Fatalf("seed TXT: %v", err)
		}
	}
	seedSOA := func(t *testing.T, domainID int32, p store.RecordsCreateSOAParams) {
		t.Helper()
		p.DomainID = pgtype.Int4{Int32: domainID, Valid: true}
		if _, err := pgContainer.Queries.RecordsCreateSOA(ctx, p); err != nil {
			t.Fatalf("seed SOA: %v", err)
		}
	}
	mockA := func(t *testing.T, name string) {
		t.Helper()
		if err := mockServer.AddRecord(name, dns.TypeA, 3600, "192.0.2.1"); err != nil {
			t.Fatalf("mock A: %v", err)
		}
	}
	// healthySOA returns a well-formed SOA with all timers in range, a date-based
	// serial, a resolvable MNAME and a valid RNAME.
	healthySOA := func(t *testing.T, name string) store.RecordsCreateSOAParams {
		t.Helper()
		mockA(t, "ns1."+name)
		return store.RecordsCreateSOAParams{
			Nameserver: "ns1." + name,
			Email:      "hostmaster." + name,
			Serial:     2026061501,
			Refresh:    7200,
			Retry:      3600,
			Expire:     1209600,
			MinimumTtl: 3600,
		}
	}

	run := func(t *testing.T, d store.DomainsCreateRow) {
		t.Helper()
		a := NewAssessor(Config{
			Store:     pgContainer.Queries,
			Logger:    testhelpers.TestLogger,
			DNSClient: dnsClient,
			Identity: observer.DomainIdentity{
				TenantID: 1, DomainID: d.ID, DomainUID: d.Uid, DomainName: d.Name,
			},
		})
		if err := a.AssessMinimumRecordSet(ctx, d.Uid); err != nil {
			t.Fatalf("AssessMinimumRecordSet failed: %v", err)
		}
	}
	get := func(t *testing.T, d store.DomainsCreateRow) []store.MinimumRecordSetFindings {
		t.Helper()
		f, err := pgContainer.Queries.AssessGetMinimumRecordSetFindingsByDomainUID(ctx,
			store.AssessGetMinimumRecordSetFindingsByDomainUIDParams{
				Uid: d.Uid, TenantID: pgtype.Int4{Int32: 1, Valid: true},
			})
		if err != nil {
			t.Fatalf("get findings: %v", err)
		}
		return f
	}
	assertOpen := func(t *testing.T, d store.DomainsCreateRow, issueType string, sev store.FindingSeverity) {
		t.Helper()
		f, ok := minRecordFindingByIssueType(get(t, d), issueType)
		if !ok {
			t.Fatalf("expected %s finding", issueType)
		}
		if f.Severity != sev {
			t.Errorf("%s: expected %s severity, got %s", issueType, sev, f.Severity)
		}
		if f.Status != store.FindingStatusOpen {
			t.Errorf("%s: expected open status, got %s", issueType, f.Status)
		}
	}

	t.Run("subdomain is skipped entirely", func(t *testing.T) {
		d := newDomain(t, "www.sub.test", store.DomainTypeSubdomain)
		run(t, d)
		if findings := get(t, d); len(findings) != 0 {
			t.Errorf("expected no findings for a subdomain, got %d", len(findings))
		}
	})

	t.Run("apex with fewer than two NS is a high finding", func(t *testing.T) {
		d := newDomain(t, "one-ns.test", store.DomainTypeTld)
		seedNS(t, d.ID, "ns1.one-ns.test")
		run(t, d)
		assertOpen(t, d, MinRecordInsufficientNS, store.FindingSeverityHigh)
	})

	t.Run("two NS records resolve the nameserver finding", func(t *testing.T) {
		d := newDomain(t, "two-ns.test", store.DomainTypeTld)
		seedNS(t, d.ID, "ns1.two-ns.test")
		seedNS(t, d.ID, "ns2.two-ns.test")
		run(t, d)
		f, ok := minRecordFindingByIssueType(get(t, d), MinRecordInsufficientNS)
		if !ok || f.Status != store.FindingStatusResolved {
			t.Errorf("expected resolved insufficient_nameservers, got %+v ok=%v", f, ok)
		}
	})

	t.Run("apex with no address record is medium", func(t *testing.T) {
		d := newDomain(t, "no-addr.test", store.DomainTypeTld)
		run(t, d)
		assertOpen(t, d, MinRecordMissingApexAddress, store.FindingSeverityMedium)
	})

	t.Run("IPv4 only yields an informational IPv6 finding", func(t *testing.T) {
		d := newDomain(t, "v4-only.test", store.DomainTypeTld)
		seedA(t, d.ID, "192.0.2.10")
		run(t, d)
		assertOpen(t, d, MinRecordMissingIPv6, store.FindingSeverityInfo)
		if f, ok := minRecordFindingByIssueType(get(t, d), MinRecordMissingApexAddress); ok &&
			f.Status == store.FindingStatusOpen {
			t.Error("did not expect open missing_apex_address when A record present")
		}
	})

	t.Run("missing SOA is medium", func(t *testing.T) {
		d := newDomain(t, "no-soa.test", store.DomainTypeTld)
		seedA(t, d.ID, "192.0.2.20")
		seedAAAA(t, d.ID, "2001:db8::20")
		run(t, d)
		assertOpen(t, d, MinRecordMissingSOA, store.FindingSeverityMedium)
	})

	t.Run("SOA timers out of range is low", func(t *testing.T) {
		d := newDomain(t, "bad-timers.test", store.DomainTypeTld)
		soa := healthySOA(t, "bad-timers.test")
		soa.Refresh = 30 // below RFC 1912 lower bound
		seedSOA(t, d.ID, soa)
		run(t, d)
		assertOpen(t, d, MinRecordSOATimers, store.FindingSeverityLow)
	})

	t.Run("non-date serial is an informational advisory", func(t *testing.T) {
		d := newDomain(t, "bad-serial.test", store.DomainTypeTld)
		soa := healthySOA(t, "bad-serial.test")
		soa.Serial = 7 // not YYYYMMDDnn
		seedSOA(t, d.ID, soa)
		run(t, d)
		assertOpen(t, d, MinRecordSOASerial, store.FindingSeverityInfo)
	})

	t.Run("unresolvable MNAME is medium", func(t *testing.T) {
		d := newDomain(t, "bad-mname.test", store.DomainTypeTld)
		soa := store.RecordsCreateSOAParams{
			Nameserver: "ns1.unreachable-mname.test", // never registered in the mock
			Email:      "hostmaster.bad-mname.test",
			Serial:     2026061501, Refresh: 7200, Retry: 3600, Expire: 1209600, MinimumTtl: 3600,
		}
		seedSOA(t, d.ID, soa)
		run(t, d)
		assertOpen(t, d, MinRecordSOAMNameUnresolvable, store.FindingSeverityMedium)
	})

	t.Run("malformed RNAME is low", func(t *testing.T) {
		d := newDomain(t, "bad-rname.test", store.DomainTypeTld)
		soa := healthySOA(t, "bad-rname.test")
		soa.Email = "not-an-email"
		seedSOA(t, d.ID, soa)
		run(t, d)
		assertOpen(t, d, MinRecordSOARName, store.FindingSeverityLow)
	})

	t.Run("email-intent without MX is low", func(t *testing.T) {
		d := newDomain(t, "mail-no-mx.test", store.DomainTypeTld)
		seedTXT(t, d.ID, "v=spf1 include:_spf.example.com ~all")
		run(t, d)
		assertOpen(t, d, MinRecordMissingMX, store.FindingSeverityLow)
	})

	t.Run("null MX with email intent is compliant", func(t *testing.T) {
		d := newDomain(t, "null-mx.test", store.DomainTypeTld)
		seedTXT(t, d.ID, "v=spf1 -all")
		seedMX(t, d.ID, 0, ".")
		run(t, d)
		if f, ok := minRecordFindingByIssueType(get(t, d), MinRecordMissingMX); ok &&
			f.Status == store.FindingStatusOpen {
			t.Error("null MX should not produce an open missing_mx finding")
		}
	})

	t.Run("no email intent and no MX produces no MX finding", func(t *testing.T) {
		d := newDomain(t, "no-mail.test", store.DomainTypeTld)
		run(t, d)
		if _, ok := minRecordFindingByIssueType(get(t, d), MinRecordMissingMX); ok {
			t.Error("did not expect a missing_mx finding for a domain with no email intent")
		}
	})

	t.Run("fully healthy apex has no open findings", func(t *testing.T) {
		d := newDomain(t, "healthy.test", store.DomainTypeTld)
		seedNS(t, d.ID, "ns1.healthy.test")
		seedNS(t, d.ID, "ns2.healthy.test")
		seedA(t, d.ID, "192.0.2.30")
		seedAAAA(t, d.ID, "2001:db8::30")
		seedSOA(t, d.ID, healthySOA(t, "healthy.test"))
		seedMX(t, d.ID, 10, "mail.healthy.test")
		run(t, d)
		for _, f := range get(t, d) {
			if f.Status == store.FindingStatusOpen {
				t.Errorf("unexpected open finding %s on a healthy apex", f.IssueType)
			}
		}
	})

	t.Run("re-running does not duplicate findings", func(t *testing.T) {
		d := newDomain(t, "idempotent.test", store.DomainTypeTld)
		run(t, d)
		run(t, d)
		count := 0
		for _, f := range get(t, d) {
			if f.IssueType == MinRecordInsufficientNS {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected exactly one insufficient_nameservers finding, got %d", count)
		}
	})
}
