package server

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestDomainTimelineHandler groups the observation log by scan: two scans of the
// same domain produce two timeline entries, newest first, each carrying only the
// changes recorded during that scan.
func TestDomainTimelineHandler(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	app := &Server{Db: pc.Queries}
	const tenantID = int32(1)

	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       "timeline.example.com",
		DomainType: store.DomainTypeSubdomain,
		Source:     store.DomainSourceUserSupplied,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}

	recordScan := func(ips []string) {
		t.Helper()
		scan, err := pc.Queries.ScansCreate(ctx, store.ScansCreateParams{
			TenantID:   tenantID,
			DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
			DomainUid:  d.Uid,
			DomainName: d.Name,
			Source:     store.DomainSourceUserSupplied,
		})
		if err != nil {
			t.Fatalf("create scan: %v", err)
		}
		tx, err := pc.Pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		rec := observer.New(pc.Queries.WithTx(tx))
		if err := rec.RecordA(ctx, observer.DomainIdentity{
			TenantID: tenantID, DomainID: d.ID, DomainUID: d.Uid, DomainName: d.Name, ScanID: scan.ID,
		}, ips, true); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("RecordA: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	recordScan([]string{"1.1.1.1"})            // scan 1: created 1.1.1.1
	recordScan([]string{"1.1.1.1", "2.2.2.2"}) // scan 2: created 2.2.2.2 (1.1.1.1 unchanged)
	recordScan([]string{"1.1.1.1", "2.2.2.2"}) // scan 3: nothing changed -> no observations

	out, err := app.handleDomainTimeline(ctxWithPrincipal(ctx, tenantID), &DomainGetInput{ID: d.Uid})
	if err != nil {
		t.Fatalf("handleDomainTimeline: %v", err)
	}
	// Scan 3 recorded no changes, so it must NOT appear: the timeline is a pure
	// change history, not a scan log.
	if len(out.Body.Scans) != 2 {
		t.Fatalf("timeline scans = %d, want 2 (no-change scan hidden)", len(out.Body.Scans))
	}

	// Newest first: scan 2 carries only the 2.2.2.2 creation.
	newest := out.Body.Scans[0]
	if len(newest.Changes) != 1 ||
		newest.Changes[0].ChangeType != "created" ||
		newest.Changes[0].EntityKey != "2.2.2.2" {
		t.Errorf("newest scan changes = %+v, want one created 2.2.2.2", newest.Changes)
	}

	// Oldest: scan 1 carries the original 1.1.1.1 creation.
	oldest := out.Body.Scans[1]
	if len(oldest.Changes) != 1 ||
		oldest.Changes[0].ChangeType != "created" ||
		oldest.Changes[0].EntityKey != "1.1.1.1" {
		t.Errorf("oldest scan changes = %+v, want one created 1.1.1.1", oldest.Changes)
	}
	if newest.ScanUID == "" || oldest.ScanUID == "" {
		t.Errorf("expected scan uids on both scans, got %q and %q", newest.ScanUID, oldest.ScanUID)
	}
	if newest.ScanUID == oldest.ScanUID {
		t.Errorf("expected distinct scan uids, both %s", newest.ScanUID)
	}
	if newest.ParentScanUID != "" {
		t.Errorf("top-level scan should have no parent_scan_uid, got %q", newest.ParentScanUID)
	}
}

// TestDomainTimeline_ParentScanUID proves the timeline resolves a child scan's
// parent to the parent's opaque uid (not the internal numeric id).
func TestDomainTimeline_ParentScanUID(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	app := &Server{Db: pc.Queries}
	const tenantID = int32(1)
	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       "lineage.example.com",
		DomainType: store.DomainTypeSubdomain,
		Source:     store.DomainSourceUserSupplied,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}

	parent, err := pc.Queries.ScansCreate(ctx, store.ScansCreateParams{
		TenantID: tenantID, DomainID: pgtype.Int4{Int32: d.ID, Valid: true},
		DomainUid: d.Uid, DomainName: d.Name, Source: store.DomainSourceUserSupplied,
	})
	if err != nil {
		t.Fatalf("create parent scan: %v", err)
	}
	child, err := pc.Queries.ScansCreate(ctx, store.ScansCreateParams{
		TenantID: tenantID, DomainID: pgtype.Int4{Int32: d.ID, Valid: true},
		DomainUid: d.Uid, DomainName: d.Name, Source: store.DomainSourceDiscovered,
		ParentScanID: pgtype.Int8{Int64: parent.ID, Valid: true},
	})
	if err != nil {
		t.Fatalf("create child scan: %v", err)
	}

	tx, err := pc.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	rec := observer.New(pc.Queries.WithTx(tx))
	if err := rec.RecordA(ctx, observer.DomainIdentity{
		TenantID: tenantID, DomainID: d.ID, DomainUID: d.Uid, DomainName: d.Name, ScanID: child.ID,
	}, []string{"9.9.9.9"}, true); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("RecordA: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	out, err := app.handleDomainTimeline(ctxWithPrincipal(ctx, tenantID), &DomainGetInput{ID: d.Uid})
	if err != nil {
		t.Fatalf("handleDomainTimeline: %v", err)
	}
	// Only the child scan recorded a change, so it is the sole entry, and its
	// parent must resolve to the parent scan's uid.
	if len(out.Body.Scans) != 1 {
		t.Fatalf("timeline scans = %d, want 1 (only child recorded a change)", len(out.Body.Scans))
	}
	if got := out.Body.Scans[0]; got.ScanUID != child.Uid {
		t.Errorf("scan uid = %q, want child %q", got.ScanUID, child.Uid)
	}
	if got := out.Body.Scans[0].ParentScanUID; got != parent.Uid {
		t.Errorf("parent_scan_uid = %q, want %q", got, parent.Uid)
	}
}
