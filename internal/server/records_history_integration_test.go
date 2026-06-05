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

// TestRecordsHistoryHandler_PreservesTimelineAcrossDeleteReadd proves the read
// path end-to-end and the preserve-on-domain-delete decision: deleting a domain
// keeps its observations (domain_id SET NULL, identity denormalized), and a
// re-added domain of the same (tenant, name) sees the prior timeline.
func TestRecordsHistoryHandler_PreservesTimelineAcrossDeleteReadd(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	app := &Server{Db: pc.Queries}
	const tenantID = int32(1)
	const name = "preserve.example.com"

	createDomain := func() store.DomainsInsertRow {
		d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
			TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
			Name:       name,
			DomainType: store.DomainTypeSubdomain,
			Source:     store.DomainSourceUserSupplied,
			Status:     store.DomainStatusActive,
		})
		if err != nil {
			t.Fatalf("create domain: %v", err)
		}
		return d
	}
	recordA := func(d store.DomainsInsertRow, ips []string) {
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
			TenantID:   tenantID,
			DomainID:   d.ID,
			DomainUID:  d.Uid,
			DomainName: d.Name,
			ScanID:     scan.ID,
		}, ips, true); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("RecordA: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	// First incarnation: observe one A record, then read the timeline via handler.
	d1 := createDomain()
	recordA(d1, []string{"1.1.1.1"})

	out, err := app.handleRecordsHistory(
		ctxWithPrincipal(ctx, tenantID),
		&RecordHistoryInput{DomainID: d1.Uid},
	)
	if err != nil {
		t.Fatalf("handleRecordsHistory: %v", err)
	}
	if len(out.Body.History) != 1 {
		t.Fatalf("history len = %d, want 1", len(out.Body.History))
	}
	if h := out.Body.History[0]; h.ChangeType != "created" || h.EntityKey != "1.1.1.1" {
		t.Errorf("history[0] = %+v, want created 1.1.1.1", h)
	}
	if h := out.Body.History[0]; h.ScanUID == "" {
		t.Errorf("history[0] should carry its scan uid, got empty")
	}

	// Delete the domain. Observations must survive with domain_id NULL.
	if _, err := pc.Queries.DomainsDeleteByID(ctx, store.DomainsDeleteByIDParams{Uid: d1.Uid, TenantID: pgtype.Int4{Int32: tenantID, Valid: true}}); err != nil {
		t.Fatalf("delete domain: %v", err)
	}
	var surviving, nullDomainID int
	if err := pc.Pool.QueryRow(
		ctx,
		`SELECT count(*), count(*) FILTER (WHERE domain_id IS NULL)
		 FROM domain_observations WHERE tenant_id=$1 AND domain_name=$2`,
		tenantID, name,
	).Scan(&surviving, &nullDomainID); err != nil {
		t.Fatalf("count surviving observations: %v", err)
	}
	if surviving != 1 || nullDomainID != 1 {
		t.Errorf("after delete: surviving=%d nullDomainID=%d, want 1 and 1 (preserved, detached)",
			surviving, nullDomainID)
	}

	// Re-add the same (tenant, name): the prior timeline must reappear via the
	// (tenant_id, domain_name) continuity key, even though domain_id differs.
	d2 := createDomain()
	if d2.ID == d1.ID {
		t.Fatalf("re-added domain reused id %d; expected a new incarnation", d2.ID)
	}
	out2, err := app.handleRecordsHistory(
		ctxWithPrincipal(ctx, tenantID),
		&RecordHistoryInput{DomainID: d2.Uid},
	)
	if err != nil {
		t.Fatalf("handleRecordsHistory after re-add: %v", err)
	}
	if len(out2.Body.History) != 1 {
		t.Fatalf("re-added history len = %d, want 1 (continuity)", len(out2.Body.History))
	}
	if h := out2.Body.History[0]; h.ChangeType != "created" || h.EntityKey != "1.1.1.1" {
		t.Errorf("re-added history[0] = %+v, want the prior created 1.1.1.1", h)
	}

	// qtype filter: a non-matching type yields an empty timeline.
	outFiltered, err := app.handleRecordsHistory(
		ctxWithPrincipal(ctx, tenantID),
		&RecordHistoryInput{DomainID: d2.Uid, QType: "cname"},
	)
	if err != nil {
		t.Fatalf("handleRecordsHistory filtered: %v", err)
	}
	if len(outFiltered.Body.History) != 0 {
		t.Errorf("cname-filtered history len = %d, want 0", len(outFiltered.Body.History))
	}
}
