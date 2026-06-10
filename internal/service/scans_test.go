package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

func seedScan(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID int32,
	d store.DomainsInsertRow,
	source store.DomainSource,
	parent pgtype.Int8,
) store.Scans {
	t.Helper()
	s, err := pc.Queries.ScansCreate(ctx, store.ScansCreateParams{
		TenantID:     tenantID,
		DomainID:     pgtype.Int4{Int32: d.ID, Valid: true},
		DomainUid:    d.Uid,
		DomainName:   d.Name,
		ParentScanID: parent,
		Source:       source,
	})
	if err != nil {
		t.Fatalf("seed scan (%s): %v", d.Name, err)
	}
	return s
}

func seedObservation(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID int32,
	d store.DomainsInsertRow,
	scanID int64,
	entityType, entityKey, changeType string,
) {
	t.Helper()
	if _, err := pc.Queries.ObservationsCreate(ctx, store.ObservationsCreateParams{
		TenantID:   tenantID,
		DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
		DomainUid:  d.Uid,
		DomainName: d.Name,
		ScanID:     pgtype.Int8{Int64: scanID, Valid: true},
		EntityType: entityType,
		EntityKey:  entityKey,
		ChangeType: changeType,
		Payload:    []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed observation (%s/%s): %v", entityType, changeType, err)
	}
}

func scanByUID(res service.TenantScansResult, uid string) (service.ScanRunView, bool) {
	for _, day := range res.Days {
		for _, s := range day.Scans {
			if s.ScanUID == uid {
				return s, true
			}
		}
	}
	return service.ScanRunView{}, false
}

func flatScanByUID(res service.FlatScansResult, uid string) (service.FlatScanView, bool) {
	for _, s := range res.Scans {
		if s.ScanUID == uid {
			return s, true
		}
	}
	return service.FlatScanView{}, false
}

func TestScansService_ListByTenantFlat(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ss := svc.ScansService()

	tenantA := createTenant(t, ctx, pc, "a-owner@example.com")
	tenantB := createTenant(t, ctx, pc, "b-owner@example.com")
	pA := ownerPrincipal(tenantA)

	acme := seedDomain(t, ctx, pc, tenantA, "acme.com")
	baseline := seedScan(t, ctx, pc, tenantA, acme, store.DomainSourceUserSupplied, pgtype.Int8{})
	seedObservation(t, ctx, pc, tenantA, acme, baseline.ID, "a_record", "a1", "created")
	changed := seedScan(t, ctx, pc, tenantA, acme, store.DomainSourceUserSupplied,
		pgtype.Int8{Int64: baseline.ID, Valid: true})
	seedObservation(t, ctx, pc, tenantA, acme, changed.ID, "a_record", "a1", "updated")
	clean := seedScan(t, ctx, pc, tenantA, acme, store.DomainSourceUserSupplied,
		pgtype.Int8{Int64: changed.ID, Valid: true})

	other := seedDomain(t, ctx, pc, tenantB, "other.com")
	otherScan := seedScan(t, ctx, pc, tenantB, other, store.DomainSourceUserSupplied, pgtype.Int8{})
	seedObservation(t, ctx, pc, tenantB, other, otherScan.ID, "a_record", "a1", "created")

	t.Run("tenant isolation and total", func(t *testing.T) {
		res, err := ss.ListByTenantFlat(ctx, pA, service.ScansListOptions{}, 25, 0)
		if err != nil {
			t.Fatalf("ListByTenantFlat: %v", err)
		}
		if res.TotalCount != 3 {
			t.Errorf("total = %d, want 3", res.TotalCount)
		}
		if _, ok := flatScanByUID(res, otherScan.Uid); ok {
			t.Fatalf("tenant A leaked tenant B scan %s", otherScan.Uid)
		}
	})

	t.Run("pagination slices but total is unpaginated", func(t *testing.T) {
		page1, err := ss.ListByTenantFlat(ctx, pA, service.ScansListOptions{}, 2, 0)
		if err != nil {
			t.Fatalf("page1: %v", err)
		}
		if page1.TotalCount != 3 || len(page1.Scans) != 2 {
			t.Errorf("page1 total/len = %d/%d, want 3/2", page1.TotalCount, len(page1.Scans))
		}
		page2, err := ss.ListByTenantFlat(ctx, pA, service.ScansListOptions{}, 2, 2)
		if err != nil {
			t.Fatalf("page2: %v", err)
		}
		if page2.TotalCount != 3 || len(page2.Scans) != 1 {
			t.Errorf("page2 total/len = %d/%d, want 3/1", page2.TotalCount, len(page2.Scans))
		}
	})

	t.Run("changed_only keeps baseline, drops clean", func(t *testing.T) {
		res, err := ss.ListByTenantFlat(ctx, pA, service.ScansListOptions{ChangedOnly: true}, 25, 0)
		if err != nil {
			t.Fatalf("changed only: %v", err)
		}
		if _, ok := flatScanByUID(res, clean.Uid); ok {
			t.Errorf("clean scan present under changed_only")
		}
		if _, ok := flatScanByUID(res, baseline.Uid); !ok {
			t.Errorf("baseline scan dropped under changed_only")
		}
	})
}

func TestScansService_ListByTenant_IsolationAndAggregates(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ss := svc.ScansService()

	tenantA := createTenant(t, ctx, pc, "a-owner@example.com")
	tenantB := createTenant(t, ctx, pc, "b-owner@example.com")
	pA := ownerPrincipal(tenantA)

	// Tenant A: acme.com has a baseline -> changed -> clean lineage; a discovered
	// domain has its own baseline.
	acme := seedDomain(t, ctx, pc, tenantA, "acme.com")
	disc := seedDomain(t, ctx, pc, tenantA, "disc.example.org")

	baseline := seedScan(t, ctx, pc, tenantA, acme, store.DomainSourceUserSupplied, pgtype.Int8{})
	seedObservation(t, ctx, pc, tenantA, acme, baseline.ID, "a_record", "a1", "created")
	seedObservation(t, ctx, pc, tenantA, acme, baseline.ID, "a_record", "a2", "created")

	changed := seedScan(t, ctx, pc, tenantA, acme, store.DomainSourceUserSupplied,
		pgtype.Int8{Int64: baseline.ID, Valid: true})
	seedObservation(t, ctx, pc, tenantA, acme, changed.ID, "a_record", "a1", "updated")
	seedObservation(t, ctx, pc, tenantA, acme, changed.ID, "txt_record", "t1", "deleted")

	clean := seedScan(t, ctx, pc, tenantA, acme, store.DomainSourceUserSupplied,
		pgtype.Int8{Int64: changed.ID, Valid: true})

	discScan := seedScan(t, ctx, pc, tenantA, disc, store.DomainSourceDiscovered, pgtype.Int8{})
	seedObservation(t, ctx, pc, tenantA, disc, discScan.ID, "a_record", "a1", "created")

	// Tenant B: a scan that must never surface for tenant A.
	other := seedDomain(t, ctx, pc, tenantB, "other.com")
	otherScan := seedScan(t, ctx, pc, tenantB, other, store.DomainSourceUserSupplied, pgtype.Int8{})
	seedObservation(t, ctx, pc, tenantB, other, otherScan.ID, "a_record", "a1", "created")

	res, err := ss.ListByTenant(ctx, pA, service.ScansListOptions{})
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}

	// Isolation: tenant B's scan is absent.
	if _, ok := scanByUID(res, otherScan.Uid); ok {
		t.Fatalf("tenant A leaked tenant B scan %s", otherScan.Uid)
	}

	if res.Totals.ScanCount != 4 {
		t.Errorf("ScanCount = %d, want 4", res.Totals.ScanCount)
	}
	if res.Totals.DomainCount != 2 {
		t.Errorf("DomainCount = %d, want 2", res.Totals.DomainCount)
	}
	if res.Totals.CleanCount != 1 {
		t.Errorf("CleanCount = %d, want 1", res.Totals.CleanCount)
	}
	if res.Totals.ChangeCount != 5 {
		t.Errorf(
			"ChangeCount = %d, want 5 (2 baseline + 2 changed + 1 disc)",
			res.Totals.ChangeCount,
		)
	}
	if res.SourceCounts["user_supplied"] != 3 || res.SourceCounts["discovered"] != 1 {
		t.Errorf("SourceCounts = %v, want user_supplied:3 discovered:1", res.SourceCounts)
	}

	if v, ok := scanByUID(res, baseline.Uid); !ok || !v.IsBaseline || v.State != "baseline" {
		t.Errorf("baseline scan: ok=%v IsBaseline=%v State=%q", ok, v.IsBaseline, v.State)
	}
	if v, ok := scanByUID(res, clean.Uid); !ok || v.State != "clean" || v.TotalChanges != 0 {
		t.Errorf("clean scan: ok=%v State=%q Total=%d", ok, v.State, v.TotalChanges)
	}
	if v, ok := scanByUID(res, changed.Uid); !ok ||
		v.UpdatedCount != 1 || v.DeletedCount != 1 || v.CreatedCount != 0 {
		t.Errorf("changed scan counts: ok=%v c/u/d=%d/%d/%d, want 0/1/1",
			ok, v.CreatedCount, v.UpdatedCount, v.DeletedCount)
	}
}

func TestScansService_ListByTenant_SourceFilterAndWindow(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ss := svc.ScansService()

	tenantID := createTenant(t, ctx, pc, "owner@example.com")
	p := ownerPrincipal(tenantID)

	userDom := seedDomain(t, ctx, pc, tenantID, "acme.com")
	discDom := seedDomain(t, ctx, pc, tenantID, "disc.example.org")

	userScan := seedScan(
		t,
		ctx,
		pc,
		tenantID,
		userDom,
		store.DomainSourceUserSupplied,
		pgtype.Int8{},
	)
	seedObservation(t, ctx, pc, tenantID, userDom, userScan.ID, "a_record", "a1", "created")
	discScan := seedScan(t, ctx, pc, tenantID, discDom, store.DomainSourceDiscovered, pgtype.Int8{})
	seedObservation(t, ctx, pc, tenantID, discDom, discScan.ID, "a_record", "a1", "created")

	t.Run("source filter narrows, SourceCounts stays faceted", func(t *testing.T) {
		res, err := ss.ListByTenant(ctx, p, service.ScansListOptions{Source: "discovered"})
		if err != nil {
			t.Fatalf("ListByTenant: %v", err)
		}
		if res.Totals.ScanCount != 1 {
			t.Errorf("ScanCount = %d, want 1", res.Totals.ScanCount)
		}
		if _, ok := scanByUID(res, discScan.Uid); !ok {
			t.Errorf("discovered scan missing under source filter")
		}
		if res.SourceCounts["user_supplied"] != 1 || res.SourceCounts["discovered"] != 1 {
			t.Errorf("SourceCounts not faceted: %v", res.SourceCounts)
		}
	})

	t.Run("window excludes scans older than the cutoff", func(t *testing.T) {
		// Backdate the discovered scan 10 days; a 1-day window must drop it.
		old := time.Now().Add(-10 * 24 * time.Hour)
		if _, err := pc.Pool.Exec(ctx,
			"UPDATE scans SET started_at = $1 WHERE id = $2", old, discScan.ID); err != nil {
			t.Fatalf("backdate scan: %v", err)
		}
		res, err := ss.ListByTenant(ctx, p, service.ScansListOptions{WindowDays: 1})
		if err != nil {
			t.Fatalf("ListByTenant: %v", err)
		}
		if _, ok := scanByUID(res, discScan.Uid); ok {
			t.Errorf("backdated scan still present in 1-day window")
		}
		if _, ok := scanByUID(res, userScan.Uid); !ok {
			t.Errorf("recent scan missing from 1-day window")
		}
	})
}
