package observer_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type notifyPayload struct {
	TenantID   int32  `json:"tenant_id"`
	DomainID   int32  `json:"domain_id"`
	DomainUID  string `json:"domain_uid"`
	DomainName string `json:"domain_name"`
	ScanID     int64  `json:"scan_id"`
	EntityType string `json:"entity_type"`
	ChangeType string `json:"change_type"`
}

// TestRecorderNotifiesOnChange asserts that a real DNS-record change fires a
// pg_notify on the domain_observations channel carrying the domain identity, so
// the server process can fan the change out to browser SSE streams.
func TestRecorderNotifiesOnChange(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	const tenantID = int32(1)
	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       "notify.example.com",
		DomainType: store.DomainTypeSubdomain,
		Source:     store.DomainSourceUserSupplied,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
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
	ident := observer.DomainIdentity{
		TenantID:   tenantID,
		DomainID:   d.ID,
		DomainUID:  d.Uid,
		DomainName: d.Name,
		ScanID:     scan.ID,
	}

	listener, err := pc.Pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire listener conn: %v", err)
	}
	defer listener.Release()
	if _, err := listener.Exec(ctx, "LISTEN domain_observations"); err != nil {
		t.Fatalf("LISTEN: %v", err)
	}

	tx, err := pc.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	rec := observer.New(pc.Queries.WithTx(tx))
	if err := rec.RecordA(ctx, ident, []string{"1.1.1.1"}, true); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("RecordA: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	n, err := listener.Conn().WaitForNotification(waitCtx)
	if err != nil {
		t.Fatalf("expected a notification, got: %v", err)
	}
	var got notifyPayload
	if err := json.Unmarshal([]byte(n.Payload), &got); err != nil {
		t.Fatalf("notification payload not JSON: %q: %v", n.Payload, err)
	}
	if got.DomainUID != d.Uid || got.TenantID != tenantID {
		t.Fatalf("notification identity = %+v, want tenant %d domain %s", got, tenantID, d.Uid)
	}
	if got.ScanID != scan.ID {
		t.Errorf("notification scan_id = %d, want %d", got.ScanID, scan.ID)
	}
}

// TestRecorderSuppressedFindingDoesNotNotify asserts that an unchanged
// re-observation (which the recorder suppresses) fires no notification — the
// notify must be gated on a real write, not merely the attempt.
func TestRecorderSuppressedFindingDoesNotNotify(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	const tenantID = int32(1)
	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       "suppress.example.com",
		DomainType: store.DomainTypeSubdomain,
		Source:     store.DomainSourceUserSupplied,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	ident := observer.DomainIdentity{
		TenantID:   tenantID,
		DomainID:   d.ID,
		DomainUID:  d.Uid,
		DomainName: d.Name,
	}

	payload := observer.PayloadJSON(map[string]any{"finding": "spf_missing"})
	rec := observer.New(pc.Queries)
	// First sighting writes (and notifies); we don't assert on it here.
	if err := rec.RecordFindingChange(ctx, ident, observer.EntitySPFFinding, "spf", payload); err != nil {
		t.Fatalf("first RecordFindingChange: %v", err)
	}

	listener, err := pc.Pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire listener conn: %v", err)
	}
	defer listener.Release()
	if _, err := listener.Exec(ctx, "LISTEN domain_observations"); err != nil {
		t.Fatalf("LISTEN: %v", err)
	}

	// Identical payload -> suppressed -> must NOT notify.
	if err := rec.RecordFindingChange(ctx, ident, observer.EntitySPFFinding, "spf", payload); err != nil {
		t.Fatalf("second RecordFindingChange: %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	n, err := listener.Conn().WaitForNotification(waitCtx)
	if err == nil {
		t.Fatalf("expected no notification for suppressed write, got: %q", n.Payload)
	}
}
