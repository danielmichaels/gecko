package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

// findingUIDByIssue returns the stable uid of a domain's finding with the given
// kind/issue type, via the per-domain service path (which now carries FindingUID).
func findingUIDByIssue(
	t *testing.T,
	ctx context.Context,
	fs *service.FindingsService,
	p *auth.Principal,
	domainUID, kind, issueType string,
) string {
	t.Helper()
	res, err := fs.ListByDomain(ctx, p, domainUID, true)
	if err != nil {
		t.Fatalf("ListByDomain: %v", err)
	}
	for _, f := range res.Findings {
		if f.Kind == kind && f.IssueType == issueType {
			return f.FindingUID
		}
	}
	t.Fatalf("no %s/%s finding on %s", kind, issueType, domainUID)
	return ""
}

func domainHasIssue(findings []service.FindingView, kind, issueType string) bool {
	for _, f := range findings {
		if f.Kind == kind && f.IssueType == issueType && !f.Suppressed {
			return true
		}
	}
	return false
}

// TestSuppressions_TenantGlobalRule verifies a tenant-global silence rule hides a
// check across every read surface for all the tenant's domains, leaves a second
// tenant untouched, and that the suppression survives a re-scan.
func TestSuppressions_TenantGlobalRule(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	fs := svc.FindingsService()
	ds := svc.DomainsService()
	ss := svc.SuppressionsService()

	tenantA := createTenant(t, ctx, pc, "a@example.com")
	tenantB := createTenant(t, ctx, pc, "b@example.com")
	pa := ownerPrincipal(tenantA)
	pb := ownerPrincipal(tenantB)

	d1 := seedDomain(t, ctx, pc, tenantA, "one.example.com")
	d2 := seedDomain(t, ctx, pc, tenantA, "two.example.com")
	db := seedDomain(t, ctx, pc, tenantB, "b.example.com")

	// Same SPF check on both tenant-A domains and on tenant B.
	seedSPFFinding(t, ctx, pc, d1.ID, store.FindingSeverityCritical, store.FindingStatusOpen, "missing_spf")
	seedSPFFinding(t, ctx, pc, d2.ID, store.FindingSeverityCritical, store.FindingStatusOpen, "missing_spf")
	seedSPFFinding(t, ctx, pc, db.ID, store.FindingSeverityCritical, store.FindingStatusOpen, "missing_spf")

	// Silence missing_spf tenant-wide for tenant A.
	if _, err := ss.CreateSilenceRule(ctx, pa, "SPF", "missing_spf", nil, "", nil); err != nil {
		t.Fatalf("CreateSilenceRule: %v", err)
	}

	// Tenant-wide list: both A domains drop the finding.
	tf, err := fs.ListByTenant(ctx, pa, service.FindingsListOptions{})
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if tf.Totals.Open != 0 {
		t.Errorf("tenant A open findings = %d, want 0 (all silenced)", tf.Totals.Open)
	}

	// Per-domain: d1 no longer reports the open finding.
	r1, err := fs.ListByDomain(ctx, pa, d1.Uid, false)
	if err != nil {
		t.Fatalf("ListByDomain d1: %v", err)
	}
	if domainHasIssue(r1.Findings, "SPF", "missing_spf") {
		t.Error("d1 still shows missing_spf after tenant-global silence")
	}
	if r1.CriticalCount != 0 {
		t.Errorf("d1 critical count = %d, want 0", r1.CriticalCount)
	}

	// Badge rollup: d1 and d2 drop to no-findings (rank 6, count 0).
	sums, err := ds.FindingsSummaryForPage(ctx, pa, []int32{d1.ID, d2.ID})
	if err != nil {
		t.Fatalf("FindingsSummaryForPage: %v", err)
	}
	for _, id := range []int32{d1.ID, d2.ID} {
		if s := sums[id]; s.Count != 0 || s.SeverityRank != 6 {
			t.Errorf("domain %d badge = (rank %d, count %d), want (6, 0)", id, s.SeverityRank, s.Count)
		}
	}

	// Tenant B is untouched.
	tfB, err := fs.ListByTenant(ctx, pb, service.FindingsListOptions{})
	if err != nil {
		t.Fatalf("ListByTenant B: %v", err)
	}
	if tfB.Totals.Open != 1 {
		t.Errorf("tenant B open findings = %d, want 1 (isolation)", tfB.Totals.Open)
	}

	// include_suppressed reveals the row but the totals stay zero.
	tfShow, err := fs.ListByTenant(ctx, pa, service.FindingsListOptions{IncludeSuppressed: true})
	if err != nil {
		t.Fatalf("ListByTenant show: %v", err)
	}
	if tfShow.Totals.Open != 0 {
		t.Errorf("with show-silenced, open total = %d, want 0", tfShow.Totals.Open)
	}
	var sawSuppressed bool
	for _, g := range tfShow.Groups {
		for _, f := range g.Findings {
			if f.Suppressed {
				sawSuppressed = true
			}
		}
	}
	if !sawSuppressed {
		t.Error("expected a suppressed row to be listed with include_suppressed")
	}

	// Survives a re-scan: re-upsert the finding (overwriting status) — still hidden.
	seedSPFFinding(t, ctx, pc, d1.ID, store.FindingSeverityCritical, store.FindingStatusOpen, "missing_spf")
	r1b, err := fs.ListByDomain(ctx, pa, d1.Uid, false)
	if err != nil {
		t.Fatalf("ListByDomain after re-scan: %v", err)
	}
	if domainHasIssue(r1b.Findings, "SPF", "missing_spf") {
		t.Error("missing_spf reappeared after re-scan — suppression should be independent of finding status")
	}
}

// TestSuppressions_PerDomainAndExpiry verifies a per-domain rule scopes to one
// domain and that an expired rule no longer applies.
func TestSuppressions_PerDomainAndExpiry(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	fs := svc.FindingsService()
	ss := svc.SuppressionsService()

	tenantID := createTenant(t, ctx, pc, "owner@example.com")
	p := ownerPrincipal(tenantID)
	d1 := seedDomain(t, ctx, pc, tenantID, "one.example.com")
	d2 := seedDomain(t, ctx, pc, tenantID, "two.example.com")

	seedDMARCFinding(t, ctx, pc, d1.ID, store.FindingSeverityMedium, store.FindingStatusOpen, "missing_dmarc")
	seedDMARCFinding(t, ctx, pc, d2.ID, store.FindingSeverityMedium, store.FindingStatusOpen, "missing_dmarc")

	d1uid := d1.Uid
	if _, err := ss.CreateSilenceRule(ctx, p, "DMARC", "missing_dmarc", &d1uid, "", nil); err != nil {
		t.Fatalf("CreateSilenceRule (domain): %v", err)
	}

	r1, _ := fs.ListByDomain(ctx, p, d1.Uid, false)
	if domainHasIssue(r1.Findings, "DMARC", "missing_dmarc") {
		t.Error("d1 should be silenced")
	}
	r2, _ := fs.ListByDomain(ctx, p, d2.Uid, false)
	if !domainHasIssue(r2.Findings, "DMARC", "missing_dmarc") {
		t.Error("d2 (sibling) must still show the finding")
	}

	// An expired rule does not apply: silence d2 with a past expiry.
	past := time.Now().Add(-time.Hour)
	d2uid := d2.Uid
	if _, err := ss.CreateSilenceRule(ctx, p, "DMARC", "missing_dmarc", &d2uid, "", &past); err != nil {
		t.Fatalf("CreateSilenceRule (expired): %v", err)
	}
	r2b, _ := fs.ListByDomain(ctx, p, d2.Uid, false)
	if !domainHasIssue(r2b.Findings, "DMARC", "missing_dmarc") {
		t.Error("expired rule must not hide the finding")
	}
}

// TestSuppressions_AcknowledgeFinding verifies an ack hides exactly one finding
// instance by uid and that a cross-tenant uid yields ErrNotFound.
func TestSuppressions_AcknowledgeFinding(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	fs := svc.FindingsService()
	ss := svc.SuppressionsService()

	tenantA := createTenant(t, ctx, pc, "a@example.com")
	tenantB := createTenant(t, ctx, pc, "b@example.com")
	pa := ownerPrincipal(tenantA)
	pb := ownerPrincipal(tenantB)

	d1 := seedDomain(t, ctx, pc, tenantA, "one.example.com")
	d2 := seedDomain(t, ctx, pc, tenantA, "two.example.com")
	seedSPFFinding(t, ctx, pc, d1.ID, store.FindingSeverityHigh, store.FindingStatusOpen, "weak_spf_policy")
	seedSPFFinding(t, ctx, pc, d2.ID, store.FindingSeverityHigh, store.FindingStatusOpen, "weak_spf_policy")

	uid := findingUIDByIssue(t, ctx, fs, pa, d1.Uid, "SPF", "weak_spf_policy")

	// Cross-tenant ack is rejected.
	if _, err := ss.AcknowledgeFinding(ctx, pb, uid, store.SuppressionStateAcknowledged, "", nil); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("cross-tenant ack: want ErrNotFound, got %v", err)
	}

	// Ack from the owning tenant hides exactly that instance.
	if _, err := ss.AcknowledgeFinding(ctx, pa, uid, store.SuppressionStateAcknowledged, "migrated", nil); err != nil {
		t.Fatalf("AcknowledgeFinding: %v", err)
	}
	r1, _ := fs.ListByDomain(ctx, pa, d1.Uid, false)
	if domainHasIssue(r1.Findings, "SPF", "weak_spf_policy") {
		t.Error("acked finding on d1 should be hidden")
	}
	r2, _ := fs.ListByDomain(ctx, pa, d2.Uid, false)
	if !domainHasIssue(r2.Findings, "SPF", "weak_spf_policy") {
		t.Error("the same check on d2 must remain visible (ack is per-instance)")
	}

	// Un-acknowledge surfaces it again.
	if err := ss.UnacknowledgeFinding(ctx, pa, uid); err != nil {
		t.Fatalf("UnacknowledgeFinding: %v", err)
	}
	r1b, _ := fs.ListByDomain(ctx, pa, d1.Uid, false)
	if !domainHasIssue(r1b.Findings, "SPF", "weak_spf_policy") {
		t.Error("finding should reappear after un-acknowledge")
	}
}

// TestSuppressions_RoleGating verifies a viewer cannot create a silence rule.
func TestSuppressions_RoleGating(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ss := svc.SuppressionsService()

	tenantID := createTenant(t, ctx, pc, "owner@example.com")
	viewer := principalWithRole(tenantID, "viewer")

	if _, err := ss.CreateSilenceRule(ctx, viewer, "SPF", "missing_spf", nil, "", nil); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("viewer create: want ErrForbidden, got %v", err)
	}
}
