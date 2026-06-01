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

	out, err := app.handleDomainTimeline(ctx, &DomainGetInput{ID: d.Uid})
	if err != nil {
		t.Fatalf("handleDomainTimeline: %v", err)
	}
	if len(out.Body.Scans) != 2 {
		t.Fatalf("timeline scans = %d, want 2", len(out.Body.Scans))
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
	if newest.ScanID == oldest.ScanID {
		t.Errorf("expected distinct scan ids, both %s", newest.ScanID)
	}
}
