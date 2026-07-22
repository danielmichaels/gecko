package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

// seedFinding writes a row directly into the generic findings table, upserting
// the backing asset first (assets aren't auto-created for a domain outside the
// migration backfill). This is what both FindingsService (ListByDomain,
// ListByTenant) and DomainsService.FindingsSummaryForPage read.
func seedFinding(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.TestDatabase,
	tenantID int32,
	domainName, checkKind, issueType, severity, title string,
) {
	t.Helper()
	asset, err := pc.Queries.AssetsUpsertDomain(ctx, store.AssetsUpsertDomainParams{
		TenantID: tenantID,
		Value:    domainName,
		Source:   "discovered",
	})
	if err != nil {
		t.Fatalf("seed finding: upsert asset (%s): %v", domainName, err)
	}
	if _, err := pc.Queries.FindingsUpsert(ctx, store.FindingsUpsertParams{
		TenantID:  tenantID,
		AssetID:   asset.ID,
		CheckKind: checkKind,
		IssueType: issueType,
		Severity:  severity,
		Title:     title,
		Details:   issueType,
	}); err != nil {
		t.Fatalf("seed finding (%s/%s/%s): %v", domainName, checkKind, issueType, err)
	}
}

func hasFindingKind(findings []service.FindingView, kind string) bool {
	for _, f := range findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

// TestDomainsService_FindingsSummaryForPage verifies the open-findings aggregate
// reflects worst severity and a domain with no finding rows reads as healthy.
func TestDomainsService_FindingsSummaryForPage(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ds := svc.DomainsService()

	tenantID := createTenant(t, ctx, pc, "owner@example.com")
	p := ownerPrincipal(tenantID)

	dCrit := seedDomain(t, ctx, pc, tenantID, "crit.example.com")
	dWarn := seedDomain(t, ctx, pc, tenantID, "warn.example.com")
	dHealthy := seedDomain(t, ctx, pc, tenantID, "healthy.example.com")
	dAXFR := seedDomain(t, ctx, pc, tenantID, "axfr.example.com")

	seedFinding(
		t, ctx, pc, tenantID, dCrit.Name,
		"email_security", "missing_spf", "critical", "missing_spf",
	)
	seedFinding(
		t, ctx, pc, tenantID, dWarn.Name,
		"email_security", "test_mode_enabled", "medium", "test_mode_enabled",
	)
	// dHealthy gets no finding rows at all: a healthy check simply has no row.
	seedFinding(
		t, ctx, pc, tenantID, dAXFR.Name,
		"zone_transfer", "zone_transfer_exposed", "high", "zone_transfer_exposed",
	)

	ids := []int32{dCrit.ID, dWarn.ID, dHealthy.ID, dAXFR.ID}
	sums, err := ds.FindingsSummaryForPage(ctx, p, ids)
	if err != nil {
		t.Fatalf("FindingsSummaryForPage: %v", err)
	}

	cases := []struct {
		name     string
		id       int32
		wantRank int32
		wantCnt  int32
	}{
		{"critical", dCrit.ID, 1, 1},
		{"warning", dWarn.ID, 3, 1},
		{"healthy", dHealthy.ID, 6, 0},
		{"axfr-possible", dAXFR.ID, 2, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sums[tc.id]
			if !ok {
				t.Fatalf("no summary row for domain %d", tc.id)
			}
			if got.SeverityRank != tc.wantRank {
				t.Errorf("severity rank = %d, want %d", got.SeverityRank, tc.wantRank)
			}
			if got.Count != tc.wantCnt {
				t.Errorf("count = %d, want %d", got.Count, tc.wantCnt)
			}
		})
	}

	t.Run("empty input", func(t *testing.T) {
		got, err := ds.FindingsSummaryForPage(ctx, p, nil)
		if err != nil {
			t.Fatalf("empty: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})
}

// TestFindingsService_ListByDomain verifies findings are aggregated across
// check kinds, sorted worst-first, bucketed for the summary strip, and
// tenant-scoped.
func TestFindingsService_ListByDomain(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	fs := svc.FindingsService()

	tenantID := createTenant(t, ctx, pc, "owner@example.com")
	p := ownerPrincipal(tenantID)
	d := seedDomain(t, ctx, pc, tenantID, "example.com")

	seedFinding(
		t, ctx, pc, tenantID, d.Name,
		"email_security", "missing_spf", "critical", "No SPF record published",
	)
	seedFinding(
		t, ctx, pc, tenantID, d.Name,
		"mta_sts", "mta_sts_not_configured", "info", "MTA-STS not configured (optional)",
	)
	seedFinding(
		t, ctx, pc, tenantID, d.Name,
		"email_security", "dmarc_missing_tags", "medium", "DMARC missing rua/ruf tags",
	)
	seedFinding(
		t, ctx, pc, tenantID, d.Name,
		"zone_transfer", "zone_transfer_exposed", "critical", "Zone transfer (AXFR) exposed",
	)
	seedFinding(
		t, ctx, pc, tenantID, d.Name,
		"certificate", "certificate_hostname_mismatch", "high", "Certificate hostname mismatch",
	)

	res, err := fs.ListByDomain(ctx, p, d.Uid)
	if err != nil {
		t.Fatalf("ListByDomain: %v", err)
	}
	if res.TotalCount != 5 {
		t.Errorf("total = %d, want 5", res.TotalCount)
	}
	if res.CriticalCount != 3 {
		t.Errorf(
			"critical = %d, want 3 (missing_spf + zone_transfer_exposed + cert high)",
			res.CriticalCount,
		)
	}
	if res.WarningCount != 1 {
		t.Errorf("warnings = %d, want 1 (dmarc medium)", res.WarningCount)
	}
	if !hasFindingKind(res.Findings, "certificate") {
		t.Errorf("expected a certificate finding in ListByDomain, got %+v", res.Findings)
	}
	if res.HealthyCount != 1 {
		t.Errorf("healthy = %d, want 1 (mta_sts info)", res.HealthyCount)
	}
	if len(res.Findings) == 0 || res.Findings[0].SevClass != "crit" {
		t.Fatalf("expected worst-first ordering with a crit head, got %+v", res.Findings)
	}
	if res.Findings[0].Title != "No SPF record published" {
		t.Errorf(
			"first finding title = %q, want %q",
			res.Findings[0].Title,
			"No SPF record published",
		)
	}

	// A different tenant must not be able to read this domain's findings.
	other := ownerPrincipal(createTenant(t, ctx, pc, "other@example.com"))
	if _, err := fs.ListByDomain(ctx, other, d.Uid); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant ListByDomain err = %v, want ErrNotFound", err)
	}
}
