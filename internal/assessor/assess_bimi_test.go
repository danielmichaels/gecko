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

func TestAssessBIMI(t *testing.T) {
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

	complianceFinding := func(t *testing.T, name, bimi, dmarc, issueType string) (store.EmailAuthComplianceFindings, bool) {
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
		if bimi != "" {
			if err := mockServer.AddRecord("default._bimi."+name, dns.TypeTXT, 3600, bimi); err != nil {
				t.Fatalf("mock BIMI: %v", err)
			}
		}
		if dmarc != "" {
			if err := mockServer.AddRecord("_dmarc."+name, dns.TypeTXT, 3600, dmarc); err != nil {
				t.Fatalf("mock DMARC: %v", err)
			}
		}
		a := NewAssessor(Config{
			Store:     pgContainer.Queries,
			Logger:    testhelpers.TestLogger,
			DNSClient: dnsClient,
			Identity:  observer.DomainIdentity{TenantID: 1, DomainID: d.ID},
		})
		if err := a.assessBIMI(ctx, assessData{handlesEmail: true, domainID: int(d.ID)}); err != nil {
			t.Fatalf("assessBIMI: %v", err)
		}
		findings, err := pgContainer.Queries.AssessGetEmailAuthComplianceFindingsByDomainUID(ctx,
			store.AssessGetEmailAuthComplianceFindingsByDomainUIDParams{
				Uid: d.Uid, TenantID: pgtype.Int4{Int32: 1, Valid: true},
			})
		if err != nil {
			t.Fatalf("get compliance findings: %v", err)
		}
		for _, f := range findings {
			if f.IssueType == issueType {
				return f, true
			}
		}
		return store.EmailAuthComplianceFindings{}, false
	}

	t.Run("valid BIMI with enforced DMARC is compliant", func(t *testing.T) {
		f, ok := complianceFinding(t, "bimi-ok.test",
			"v=BIMI1; l=https://bimi-ok.test/logo.svg; a=https://bimi-ok.test/vmc.pem",
			"v=DMARC1; p=reject; rua=mailto:r@bimi-ok.test", BIMICompliant)
		if !ok {
			t.Fatalf("expected bimi_compliant finding")
		}
		if f.AuthType != BIMIAuthType || f.Status != store.FindingStatusClosed {
			t.Errorf("expected BIMI/closed, got %s/%s", f.AuthType, f.Status)
		}
	})

	t.Run("BIMI without enforced DMARC is flagged", func(t *testing.T) {
		f, ok := complianceFinding(t, "bimi-noenforce.test",
			"v=BIMI1; l=https://bimi-noenforce.test/logo.svg",
			"v=DMARC1; p=none; rua=mailto:r@bimi-noenforce.test", BIMIRequiresEnforcedDMARC)
		if !ok {
			t.Fatalf("expected bimi_requires_enforced_dmarc finding")
		}
		if f.Severity != store.FindingSeverityMedium || f.Status != store.FindingStatusOpen {
			t.Errorf("expected medium/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("non-HTTPS logo is flagged", func(t *testing.T) {
		f, ok := complianceFinding(t, "bimi-badlogo.test",
			"v=BIMI1; l=http://bimi-badlogo.test/logo.svg",
			"v=DMARC1; p=reject; rua=mailto:r@bimi-badlogo.test", BIMIInvalidLogo)
		if !ok {
			t.Fatalf("expected bimi_invalid_logo finding")
		}
		if f.Severity != store.FindingSeverityLow || f.Status != store.FindingStatusOpen {
			t.Errorf("expected low/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("absent BIMI is informational and not-applicable", func(t *testing.T) {
		f, ok := complianceFinding(t, "bimi-absent.test", "",
			"v=DMARC1; p=reject", BIMINotConfigured)
		if !ok {
			t.Fatalf("expected bimi_not_configured finding")
		}
		if f.Severity != store.FindingSeverityInfo || f.Status != store.FindingStatusNotApplicable {
			t.Errorf("expected info/not_applicable, got %s/%s", f.Severity, f.Status)
		}
	})
}
