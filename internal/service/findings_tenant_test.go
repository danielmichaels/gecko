package service_test

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

// TestFindingsService_ListByTenant exercises the tenant-wide roll-up against a
// real database: the cross-tenant isolation invariant, the compliant toggle, the
// severity/kind/domain filters, and the data-driven KindCounts.
func TestFindingsService_ListByTenant(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	fs := svc.FindingsService()

	tenantA := createTenant(t, ctx, pc, "a-owner@example.com")
	tenantB := createTenant(t, ctx, pc, "b-owner@example.com")
	pA := ownerPrincipal(tenantA)
	pB := ownerPrincipal(tenantB)

	acme := seedDomain(t, ctx, pc, tenantA, "acme.com")
	blog := seedDomain(t, ctx, pc, tenantA, "blog.example.org")
	secret := seedDomain(t, ctx, pc, tenantB, "secret.io")

	// Tenant A: a critical + high on acme, a medium on blog, plus a possible AXFR
	// on acme and (compliant) closed-SPF + refused-AXFR on blog.
	seedSPFFinding(
		t,
		ctx,
		pc,
		acme.ID,
		store.FindingSeverityCritical,
		store.FindingStatusOpen,
		"missing_spf",
	)
	seedDMARCFinding(
		t,
		ctx,
		pc,
		acme.ID,
		store.FindingSeverityHigh,
		store.FindingStatusOpen,
		"weak_dmarc_policy",
	)
	seedZoneTransferFinding(t, ctx, pc, acme.ID, "ns1.acme.com", true)
	seedDKIMFinding(
		t,
		ctx,
		pc,
		blog.ID,
		store.FindingSeverityMedium,
		store.FindingStatusOpen,
		"test_mode_enabled",
	)
	seedSPFFinding(
		t,
		ctx,
		pc,
		blog.ID,
		store.FindingSeverityInfo,
		store.FindingStatusClosed,
		"spf_compliant",
	)
	seedZoneTransferFinding(t, ctx, pc, blog.ID, "ns1.blog.example.org", false)

	// Tenant B: a finding that must never appear in tenant A's roll-up.
	seedSPFFinding(
		t,
		ctx,
		pc,
		secret.ID,
		store.FindingSeverityCritical,
		store.FindingStatusOpen,
		"missing_spf",
	)

	t.Run("tenant isolation", func(t *testing.T) {
		resA, err := fs.ListByTenant(ctx, pA, service.FindingsListOptions{})
		if err != nil {
			t.Fatalf("ListByTenant(A): %v", err)
		}
		for _, g := range resA.Groups {
			if g.DomainName == "secret.io" {
				t.Fatalf("tenant A leaked tenant B domain: %q", g.DomainName)
			}
		}

		resB, err := fs.ListByTenant(ctx, pB, service.FindingsListOptions{})
		if err != nil {
			t.Fatalf("ListByTenant(B): %v", err)
		}
		if len(resB.Groups) != 1 || resB.Groups[0].DomainName != "secret.io" {
			t.Fatalf("tenant B groups = %v, want [secret.io]", groupNames(resB.Groups))
		}
	})

	t.Run("compliant toggle", func(t *testing.T) {
		open, err := fs.ListByTenant(ctx, pA, service.FindingsListOptions{IncludeCompliant: false})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		// acme: SPF + DMARC + possible AXFR (3); blog: DKIM only (1). Compliant SPF
		// and refused AXFR on blog are hidden.
		if open.Totals.Open != 4 {
			t.Errorf("open total = %d, want 4 (%v)", open.Totals.Open, groupNames(open.Groups))
		}

		all, err := fs.ListByTenant(ctx, pA, service.FindingsListOptions{IncludeCompliant: true})
		if err != nil {
			t.Fatalf("all: %v", err)
		}
		// Adds blog's compliant SPF and refused AXFR.
		if all.Totals.Open != 6 {
			t.Errorf("compliant total = %d, want 6", all.Totals.Open)
		}
	})

	t.Run("worst-domain-first", func(t *testing.T) {
		res, err := fs.ListByTenant(ctx, pA, service.FindingsListOptions{})
		if err != nil {
			t.Fatalf("ListByTenant: %v", err)
		}
		if len(res.Groups) != 2 || res.Groups[0].DomainName != "acme.com" {
			t.Errorf("groups = %v, want acme.com first", groupNames(res.Groups))
		}
	})

	t.Run("filters", func(t *testing.T) {
		crit, _ := fs.ListByTenant(ctx, pA, service.FindingsListOptions{Severity: "crit"})
		if crit.Totals.Open != 1 || crit.Totals.Critical != 1 {
			t.Errorf(
				"severity crit: open/crit = %d/%d, want 1/1",
				crit.Totals.Open,
				crit.Totals.Critical,
			)
		}

		dmarc, _ := fs.ListByTenant(ctx, pA, service.FindingsListOptions{Kind: "DMARC"})
		if dmarc.Totals.Open != 1 {
			t.Errorf("kind DMARC: open = %d, want 1", dmarc.Totals.Open)
		}

		dom, _ := fs.ListByTenant(ctx, pA, service.FindingsListOptions{DomainQuery: "blog"})
		if dom.Totals.DomainCount != 1 || dom.Groups[0].DomainName != "blog.example.org" {
			t.Errorf("domain filter groups = %v, want [blog.example.org]", groupNames(dom.Groups))
		}
	})

	t.Run("KindCounts reflects live kinds", func(t *testing.T) {
		res, _ := fs.ListByTenant(ctx, pA, service.FindingsListOptions{})
		for _, kind := range []string{"SPF", "DMARC", "DKIM", "ZONE"} {
			if res.KindCounts[kind] == 0 {
				t.Errorf("KindCounts[%s] = 0, want >0 (%v)", kind, res.KindCounts)
			}
		}
	})
}

// TestFindingsService_ListByTenantFlat exercises the flat, paginated API listing:
// cross-tenant isolation, the unpaginated total, the page slice, and filter parity
// with the grouped path.
func TestFindingsService_ListByTenantFlat(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	fs := svc.FindingsService()

	tenantA := createTenant(t, ctx, pc, "a-owner@example.com")
	tenantB := createTenant(t, ctx, pc, "b-owner@example.com")
	pA := ownerPrincipal(tenantA)
	pB := ownerPrincipal(tenantB)

	acme := seedDomain(t, ctx, pc, tenantA, "acme.com")
	secret := seedDomain(t, ctx, pc, tenantB, "secret.io")

	seedSPFFinding(
		t,
		ctx,
		pc,
		acme.ID,
		store.FindingSeverityCritical,
		store.FindingStatusOpen,
		"missing_spf",
	)
	seedDMARCFinding(
		t,
		ctx,
		pc,
		acme.ID,
		store.FindingSeverityHigh,
		store.FindingStatusOpen,
		"weak_dmarc_policy",
	)
	seedDKIMFinding(
		t,
		ctx,
		pc,
		acme.ID,
		store.FindingSeverityMedium,
		store.FindingStatusOpen,
		"test_mode_enabled",
	)
	seedSPFFinding(
		t,
		ctx,
		pc,
		secret.ID,
		store.FindingSeverityCritical,
		store.FindingStatusOpen,
		"missing_spf",
	)

	t.Run("tenant isolation", func(t *testing.T) {
		res, err := fs.ListByTenantFlat(ctx, pA, service.FindingsListOptions{}, 25, 0)
		if err != nil {
			t.Fatalf("ListByTenantFlat(A): %v", err)
		}
		if res.TotalCount != 3 {
			t.Errorf("total = %d, want 3", res.TotalCount)
		}
		for _, f := range res.Findings {
			if f.DomainName == "secret.io" {
				t.Fatalf("tenant A leaked tenant B finding for %q", f.DomainName)
			}
		}

		resB, err := fs.ListByTenantFlat(ctx, pB, service.FindingsListOptions{}, 25, 0)
		if err != nil {
			t.Fatalf("ListByTenantFlat(B): %v", err)
		}
		if resB.TotalCount != 1 || resB.Findings[0].DomainName != "secret.io" {
			t.Fatalf("tenant B = %d findings, want 1 (secret.io)", resB.TotalCount)
		}
	})

	t.Run("pagination slices but total is unpaginated", func(t *testing.T) {
		page1, err := fs.ListByTenantFlat(ctx, pA, service.FindingsListOptions{}, 2, 0)
		if err != nil {
			t.Fatalf("page1: %v", err)
		}
		if page1.TotalCount != 3 || len(page1.Findings) != 2 {
			t.Errorf("page1 total/len = %d/%d, want 3/2", page1.TotalCount, len(page1.Findings))
		}
		page2, err := fs.ListByTenantFlat(ctx, pA, service.FindingsListOptions{}, 2, 2)
		if err != nil {
			t.Fatalf("page2: %v", err)
		}
		if page2.TotalCount != 3 || len(page2.Findings) != 1 {
			t.Errorf("page2 total/len = %d/%d, want 3/1", page2.TotalCount, len(page2.Findings))
		}
	})

	t.Run("offset past end returns empty", func(t *testing.T) {
		res, err := fs.ListByTenantFlat(ctx, pA, service.FindingsListOptions{}, 25, 100)
		if err != nil {
			t.Fatalf("offset past end: %v", err)
		}
		if res.TotalCount != 3 || len(res.Findings) != 0 {
			t.Errorf("total/len = %d/%d, want 3/0", res.TotalCount, len(res.Findings))
		}
	})

	t.Run("severity filter parity", func(t *testing.T) {
		res, err := fs.ListByTenantFlat(
			ctx,
			pA,
			service.FindingsListOptions{Severity: "crit"},
			25,
			0,
		)
		if err != nil {
			t.Fatalf("severity filter: %v", err)
		}
		if res.TotalCount != 1 || res.Findings[0].Tier != "crit" {
			t.Errorf("crit filter total = %d, want 1 crit finding", res.TotalCount)
		}
	})
}

func groupNames(groups []service.DomainFindingGroup) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g.DomainName
	}
	return out
}
