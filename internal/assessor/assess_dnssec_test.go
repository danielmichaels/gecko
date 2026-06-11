package assessor

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/scanner"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

func dnssecFindingByIssueType(
	findings []store.DnssecFindings,
	issueType string,
) (store.DnssecFindings, bool) {
	for _, f := range findings {
		if f.IssueType == issueType {
			return f, true
		}
	}
	return store.DnssecFindings{}, false
}

func TestAssessDNSSEC(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

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

	assess := func(t *testing.T, d store.DomainsCreateRow) []store.DnssecFindings {
		t.Helper()
		ident := observer.DomainIdentity{
			TenantID:   1,
			DomainID:   d.ID,
			DomainUID:  d.Uid,
			DomainName: d.Name,
		}
		a := NewAssessor(
			Config{Store: pgContainer.Queries, Logger: testhelpers.TestLogger, Identity: ident},
		)
		if err := a.AssessDNSSEC(ctx, d.Uid); err != nil {
			t.Fatalf("AssessDNSSEC failed: %v", err)
		}
		findings, err := pgContainer.Queries.AssessGetDNSSECFindingsByDomainUID(
			ctx,
			store.AssessGetDNSSECFindingsByDomainUIDParams{
				Uid:      d.Uid,
				TenantID: pgtype.Int4{Int32: 1, Valid: true},
			},
		)
		if err != nil {
			t.Fatalf("Failed to get dnssec findings: %v", err)
		}
		return findings
	}

	t.Run("validation failure is a broken-chain high finding", func(t *testing.T) {
		d := newDomain(t, "broken-dnssec.test")
		_, err := pgContainer.Queries.ScannersStoreDNSSECResult(
			ctx,
			store.ScannersStoreDNSSECResultParams{
				DomainID: pgtype.Int4{Int32: d.ID, Valid: true},
				Status:   "DS record does not match DNSKEY",
				ValidationError: pgtype.Text{
					String: "DS record does not match DNSKEY",
					Valid:  true,
				},
				HasDnskey:  true,
				HasDs:      true,
				HasRrsig:   true,
				Algorithms: []string{"13"},
			},
		)
		if err != nil {
			t.Fatalf("Failed to store dnssec result: %v", err)
		}
		findings := assess(t, d)
		f, ok := dnssecFindingByIssueType(findings, DNSSECBrokenChain)
		if !ok {
			t.Fatalf("expected broken-chain finding")
		}
		if f.Severity != store.FindingSeverityHigh {
			t.Errorf("expected high severity, got %s", f.Severity)
		}
		if f.Status != store.FindingStatusOpen {
			t.Errorf("expected open status, got %s", f.Status)
		}
	})

	t.Run("absent DNSSEC is an informational not-enabled finding", func(t *testing.T) {
		d := newDomain(t, "no-dnssec.test")
		_, err := pgContainer.Queries.ScannersStoreDNSSECResult(
			ctx,
			store.ScannersStoreDNSSECResultParams{
				DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
				Status:     scanner.DNSSECNotImplemented,
				Algorithms: []string{},
			},
		)
		if err != nil {
			t.Fatalf("Failed to store dnssec result: %v", err)
		}
		findings := assess(t, d)
		f, ok := dnssecFindingByIssueType(findings, DNSSECNotEnabled)
		if !ok {
			t.Fatalf("expected not-enabled finding")
		}
		if f.Severity != store.FindingSeverityInfo {
			t.Errorf("expected info severity, got %s", f.Severity)
		}
		if f.Status != store.FindingStatusCompliant {
			t.Errorf("expected compliant status, got %s", f.Status)
		}
		if _, present := dnssecFindingByIssueType(findings, DNSSECBrokenChain); present {
			t.Error("did not expect a broken-chain finding for absent DNSSEC")
		}
	})

	t.Run(
		"fully implemented with deprecated algorithm yields enabled + weak-algorithm",
		func(t *testing.T) {
			d := newDomain(t, "weak-algo-dnssec.test")
			_, err := pgContainer.Queries.ScannersStoreDNSSECResult(
				ctx,
				store.ScannersStoreDNSSECResultParams{
					DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
					Status:     scanner.DNSSECFullyImplemented,
					HasDnskey:  true,
					HasDs:      true,
					HasRrsig:   true,
					Algorithms: []string{"5"}, // RSASHA1, deprecated
				},
			)
			if err != nil {
				t.Fatalf("Failed to store dnssec result: %v", err)
			}
			findings := assess(t, d)

			enabled, ok := dnssecFindingByIssueType(findings, DNSSECEnabled)
			if !ok {
				t.Fatalf("expected enabled finding")
			}
			if enabled.Severity != store.FindingSeverityInfo ||
				enabled.Status != store.FindingStatusCompliant {
				t.Errorf(
					"expected enabled info/compliant, got %s/%s",
					enabled.Severity,
					enabled.Status,
				)
			}

			weak, ok := dnssecFindingByIssueType(findings, DNSSECWeakAlgorithm)
			if !ok {
				t.Fatalf("expected weak-algorithm finding")
			}
			if weak.Severity != store.FindingSeverityMedium ||
				weak.Status != store.FindingStatusOpen {
				t.Errorf("expected weak-algo medium/open, got %s/%s", weak.Severity, weak.Status)
			}
		},
	)
}
