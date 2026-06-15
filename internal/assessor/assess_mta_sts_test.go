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

func TestAssessMTASTSAndTLSRPT(t *testing.T) {
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

	policyURL := func(domain string) string {
		return "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	}

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
			t.Fatalf("create domain: %v", err)
		}
		return d
	}

	finding := func(t *testing.T, d store.DomainsCreateRow, authType, issueType string) (store.EmailAuthComplianceFindings, bool) {
		t.Helper()
		fs, err := pgContainer.Queries.AssessGetEmailAuthComplianceFindingsByDomainUID(ctx,
			store.AssessGetEmailAuthComplianceFindingsByDomainUIDParams{
				Uid: d.Uid, TenantID: pgtype.Int4{Int32: 1, Valid: true},
			})
		if err != nil {
			t.Fatalf("get compliance findings: %v", err)
		}
		for _, f := range fs {
			if f.AuthType == authType && f.IssueType == issueType {
				return f, true
			}
		}
		return store.EmailAuthComplianceFindings{}, false
	}

	runMTASTS := func(t *testing.T, d store.DomainsCreateRow, prober HTTPProber, mx []store.MxRecords) {
		t.Helper()
		a := NewAssessor(Config{
			Store:      pgContainer.Queries,
			Logger:     testhelpers.TestLogger,
			DNSClient:  dnsClient,
			HTTPProber: prober,
			Identity:   observer.DomainIdentity{TenantID: 1, DomainID: d.ID},
		})
		if err := a.assessMTASTS(ctx, assessData{handlesEmail: true, domainID: int(d.ID), mxRecords: mx}); err != nil {
			t.Fatalf("assessMTASTS: %v", err)
		}
	}
	runTLSRPT := func(t *testing.T, d store.DomainsCreateRow) {
		t.Helper()
		a := NewAssessor(Config{
			Store:     pgContainer.Queries,
			Logger:    testhelpers.TestLogger,
			DNSClient: dnsClient,
			Identity:  observer.DomainIdentity{TenantID: 1, DomainID: d.ID},
		})
		if err := a.assessTLSRPT(ctx, assessData{handlesEmail: true, domainID: int(d.ID)}); err != nil {
			t.Fatalf("assessTLSRPT: %v", err)
		}
	}

	mxOf := func(host string) []store.MxRecords {
		return []store.MxRecords{{Preference: 10, Target: host}}
	}

	t.Run("no MTA-STS record is informational and not-applicable", func(t *testing.T) {
		d := newDomain(t, "no-mtasts.test")
		runMTASTS(t, d, fakeProber{}, mxOf("mail.no-mtasts.test"))

		f, ok := finding(t, d, MTASTSAuthType, MTASTSNotConfigured)
		if !ok {
			t.Fatalf("expected mta_sts_not_configured finding")
		}
		if f.Severity != store.FindingSeverityInfo || f.Status != store.FindingStatusNotApplicable {
			t.Errorf("expected info/not_applicable, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("enforce policy with matching MX is compliant", func(t *testing.T) {
		d := newDomain(t, "good-mtasts.test")
		if err := mockServer.AddRecord("_mta-sts."+d.Name, dns.TypeTXT, 3600, "v=STSv1; id=20240101T000000Z"); err != nil {
			t.Fatalf("mock txt: %v", err)
		}
		prober := fakeProber{results: map[string]ProbeResult{
			policyURL(d.Name): {
				Reached:    true,
				StatusCode: 200,
				Body:       "version: STSv1\nmode: enforce\nmx: mail.good-mtasts.test\nmax_age: 604800\n",
			},
		}}
		runMTASTS(t, d, prober, mxOf("mail.good-mtasts.test"))

		f, ok := finding(t, d, MTASTSAuthType, MTASTSCompliant)
		if !ok {
			t.Fatalf("expected mta_sts_compliant finding")
		}
		if f.Status != store.FindingStatusClosed {
			t.Errorf("expected closed, got %s", f.Status)
		}
	})

	t.Run("testing mode is flagged as not enforcing", func(t *testing.T) {
		d := newDomain(t, "testing-mtasts.test")
		if err := mockServer.AddRecord("_mta-sts."+d.Name, dns.TypeTXT, 3600, "v=STSv1; id=abc"); err != nil {
			t.Fatalf("mock txt: %v", err)
		}
		prober := fakeProber{results: map[string]ProbeResult{
			policyURL(d.Name): {
				Reached:    true,
				StatusCode: 200,
				Body:       "version: STSv1\nmode: testing\nmx: mail.testing-mtasts.test\nmax_age: 604800\n",
			},
		}}
		runMTASTS(t, d, prober, mxOf("mail.testing-mtasts.test"))

		f, ok := finding(t, d, MTASTSAuthType, MTASTSModeNotEnforcing)
		if !ok {
			t.Fatalf("expected mta_sts_mode_not_enforcing finding")
		}
		if f.Severity != store.FindingSeverityLow || f.Status != store.FindingStatusOpen {
			t.Errorf("expected low/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("policy MX not covering actual MX is a medium mismatch", func(t *testing.T) {
		d := newDomain(t, "mismatch-mtasts.test")
		if err := mockServer.AddRecord("_mta-sts."+d.Name, dns.TypeTXT, 3600, "v=STSv1; id=abc"); err != nil {
			t.Fatalf("mock txt: %v", err)
		}
		prober := fakeProber{results: map[string]ProbeResult{
			policyURL(d.Name): {
				Reached:    true,
				StatusCode: 200,
				Body:       "version: STSv1\nmode: enforce\nmx: other-host.example\nmax_age: 604800\n",
			},
		}}
		runMTASTS(t, d, prober, mxOf("mail.mismatch-mtasts.test"))

		f, ok := finding(t, d, MTASTSAuthType, MTASTSMXMismatch)
		if !ok {
			t.Fatalf("expected mta_sts_mx_mismatch finding")
		}
		if f.Severity != store.FindingSeverityMedium || f.Status != store.FindingStatusOpen {
			t.Errorf("expected medium/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("unreachable policy is flagged", func(t *testing.T) {
		d := newDomain(t, "unreachable-mtasts.test")
		if err := mockServer.AddRecord("_mta-sts."+d.Name, dns.TypeTXT, 3600, "v=STSv1; id=abc"); err != nil {
			t.Fatalf("mock txt: %v", err)
		}
		runMTASTS(t, d, fakeProber{}, mxOf("mail.unreachable-mtasts.test"))

		f, ok := finding(t, d, MTASTSAuthType, MTASTSPolicyUnreachable)
		if !ok {
			t.Fatalf("expected mta_sts_policy_unreachable finding")
		}
		if f.Severity != store.FindingSeverityLow || f.Status != store.FindingStatusOpen {
			t.Errorf("expected low/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("no TLS-RPT record is informational", func(t *testing.T) {
		d := newDomain(t, "no-tlsrpt.test")
		runTLSRPT(t, d)

		f, ok := finding(t, d, TLSRPTAuthType, TLSRPTNotConfigured)
		if !ok {
			t.Fatalf("expected tls_rpt_not_configured finding")
		}
		if f.Severity != store.FindingSeverityInfo {
			t.Errorf("expected info, got %s", f.Severity)
		}
	})

	t.Run("valid TLS-RPT record is compliant", func(t *testing.T) {
		d := newDomain(t, "good-tlsrpt.test")
		if err := mockServer.AddRecord("_smtp._tls."+d.Name, dns.TypeTXT, 3600, "v=TLSRPTv1; rua=mailto:tls@good-tlsrpt.test"); err != nil {
			t.Fatalf("mock txt: %v", err)
		}
		runTLSRPT(t, d)

		f, ok := finding(t, d, TLSRPTAuthType, TLSRPTCompliant)
		if !ok {
			t.Fatalf("expected tls_rpt_compliant finding")
		}
		if f.Status != store.FindingStatusClosed {
			t.Errorf("expected closed, got %s", f.Status)
		}
	})
}
