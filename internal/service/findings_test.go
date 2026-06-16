package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

func seedDMARCFinding(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
) {
	t.Helper()
	if _, err := pc.Queries.AssessCreateDMARCFinding(ctx, store.AssessCreateDMARCFindingParams{
		DomainID:  pgtype.Int4{Int32: domainID, Valid: true},
		Severity:  severity,
		Status:    status,
		IssueType: issueType,
		Details:   pgtype.Text{String: issueType, Valid: true},
	}); err != nil {
		t.Fatalf("seed dmarc finding (domain %d): %v", domainID, err)
	}
}

func seedSPFFinding(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
) {
	t.Helper()
	if _, err := pc.Queries.AssessCreateSPFFinding(ctx, store.AssessCreateSPFFindingParams{
		DomainID:  pgtype.Int4{Int32: domainID, Valid: true},
		Severity:  severity,
		Status:    status,
		IssueType: issueType,
		Details:   pgtype.Text{String: issueType, Valid: true},
	}); err != nil {
		t.Fatalf("seed spf finding (domain %d): %v", domainID, err)
	}
}

func seedDKIMFinding(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
) {
	t.Helper()
	if _, err := pc.Queries.AssessCreateDKIMFindingNoSelector(ctx, store.AssessCreateDKIMFindingNoSelectorParams{
		DomainID:  pgtype.Int4{Int32: domainID, Valid: true},
		Severity:  severity,
		Status:    status,
		IssueType: issueType,
		Details:   pgtype.Text{String: issueType, Valid: true},
	}); err != nil {
		t.Fatalf("seed dkim finding (domain %d): %v", domainID, err)
	}
}

func seedZoneTransferFinding(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	domainID int32,
	nameserver string,
	possible bool,
) {
	t.Helper()
	if _, err := pc.Queries.StoreZoneTransferFinding(ctx, store.StoreZoneTransferFindingParams{
		DomainID:             pgtype.Int4{Int32: domainID, Valid: true},
		Severity:             store.FindingSeverityHigh,
		Status:               store.FindingStatusOpen,
		Nameserver:           nameserver,
		ZoneTransferPossible: possible,
		TransferType:         store.TransferTypeAXFR,
		Details:              pgtype.Text{String: "zone transfer", Valid: true},
	}); err != nil {
		t.Fatalf("seed zone transfer finding (domain %d): %v", domainID, err)
	}
}

func seedCertificateFinding(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
) {
	t.Helper()
	if _, err := pc.Queries.AssessCreateCertificateFinding(ctx, store.AssessCreateCertificateFindingParams{
		DomainID:  pgtype.Int4{Int32: domainID, Valid: true},
		Severity:  severity,
		Status:    status,
		IssueType: issueType,
		Details:   pgtype.Text{String: issueType, Valid: true},
	}); err != nil {
		t.Fatalf("seed certificate finding (domain %d): %v", domainID, err)
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
// reflects worst severity, ignores compliant/closed findings, and only counts an
// AXFR finding when the transfer is actually possible.
func TestDomainsService_FindingsSummaryForPage(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
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

	// dCrit: critical open SPF.
	seedSPFFinding(
		t,
		ctx,
		pc,
		dCrit.ID,
		store.FindingSeverityCritical,
		store.FindingStatusOpen,
		"missing_spf",
	)
	// dWarn: medium open DKIM.
	seedDKIMFinding(
		t,
		ctx,
		pc,
		dWarn.ID,
		store.FindingSeverityMedium,
		store.FindingStatusOpen,
		"test_mode_enabled",
	)
	// dHealthy: compliant SPF (info/closed) + a refused AXFR — neither should count.
	seedSPFFinding(
		t,
		ctx,
		pc,
		dHealthy.ID,
		store.FindingSeverityInfo,
		store.FindingStatusClosed,
		"spf_compliant",
	)
	seedZoneTransferFinding(t, ctx, pc, dHealthy.ID, "ns1.healthy.example.com", false)
	// dAXFR: a possible zone transfer (high).
	seedZoneTransferFinding(t, ctx, pc, dAXFR.ID, "ns1.axfr.example.com", true)

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

// TestFindingsService_ListByDomain verifies findings are aggregated across types,
// sorted worst-first, bucketed for the summary strip, and tenant-scoped.
func TestFindingsService_ListByDomain(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	fs := svc.FindingsService()

	tenantID := createTenant(t, ctx, pc, "owner@example.com")
	p := ownerPrincipal(tenantID)
	d := seedDomain(t, ctx, pc, tenantID, "example.com")

	seedSPFFinding(
		t,
		ctx,
		pc,
		d.ID,
		store.FindingSeverityCritical,
		store.FindingStatusOpen,
		"missing_spf",
	)
	seedSPFFinding(
		t,
		ctx,
		pc,
		d.ID,
		store.FindingSeverityInfo,
		store.FindingStatusClosed,
		"spf_compliant",
	)
	seedDMARCFinding(
		t,
		ctx,
		pc,
		d.ID,
		store.FindingSeverityMedium,
		store.FindingStatusOpen,
		"dmarc_missing_tags",
	)
	seedZoneTransferFinding(t, ctx, pc, d.ID, "ns1.example.com", true)
	seedCertificateFinding(
		t,
		ctx,
		pc,
		d.ID,
		store.FindingSeverityHigh,
		store.FindingStatusOpen,
		"certificate_hostname_mismatch",
	)

	res, err := fs.ListByDomain(ctx, p, d.Uid, false)
	if err != nil {
		t.Fatalf("ListByDomain: %v", err)
	}
	if res.TotalCount != 5 {
		t.Errorf("total = %d, want 5", res.TotalCount)
	}
	if res.CriticalCount != 3 {
		t.Errorf(
			"critical = %d, want 3 (missing_spf + possible AXFR + cert high)",
			res.CriticalCount,
		)
	}
	if res.WarningCount != 1 {
		t.Errorf("warnings = %d, want 1 (dmarc medium)", res.WarningCount)
	}
	if !hasFindingKind(res.Findings, "CERT") {
		t.Errorf("expected a CERT finding in ListByDomain, got %+v", res.Findings)
	}
	if res.HealthyCount != 1 {
		t.Errorf("healthy = %d, want 1 (spf_compliant)", res.HealthyCount)
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
	if _, err := fs.ListByDomain(ctx, other, d.Uid, false); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant ListByDomain err = %v, want ErrNotFound", err)
	}
}
