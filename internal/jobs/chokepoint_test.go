package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestEnqueueDomainScan_StampsSchedule locks in the chokepoint contract: every
// scan that EnqueueDomainScan actually creates — manual, discovered, or scheduled
// — stamps last_scanned_at and advances next_scan_at by the effective interval,
// and an 'off' domain is stamped but left out of the schedule (cursor NULL). This
// is the single place that fixes the updated_at proxy for all triggers.
func TestEnqueueDomainScan_StampsSchedule(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	rc, err := New(ctx, Config{PgxPool: pc.Pool, Logger: testhelpers.TestLogger, Store: q})
	if err != nil {
		t.Fatalf("create river client: %v", err)
	}

	tid := seedStatsTenant(t, ctx, q, "chokepoint@sched.test")
	if _, err := q.TenantSettingsUpsert(ctx, store.TenantSettingsUpsertParams{
		TenantID: tid, DefaultScanFrequency: store.ScanFrequencyDaily,
	}); err != nil {
		t.Fatalf("upsert settings: %v", err)
	}

	createDomain := func(name string) store.DomainsInsertRow {
		d, err := q.DomainsInsert(ctx, store.DomainsInsertParams{
			TenantID:   pgtype.Int4{Int32: tid, Valid: true},
			Name:       name,
			DomainType: store.DomainTypeSubdomain,
			Source:     store.DomainSourceUserSupplied,
			Status:     store.DomainStatusActive,
		})
		if err != nil {
			t.Fatalf("create domain %q: %v", name, err)
		}
		return d
	}
	enqueue := func(d store.DomainsInsertRow, opts DomainScanOptions) {
		tx, err := pc.Pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		st := q.WithTx(tx)
		if _, err := EnqueueDomainScan(ctx, rc, tx, st, DomainScanTarget{
			TenantID: tid, DomainID: d.ID, DomainUID: d.Uid, DomainName: d.Name, Status: d.Status,
		}, opts); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("EnqueueDomainScan: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	stamps := func(id int32) (last, next pgtype.Timestamptz) {
		const q = `SELECT last_scanned_at, next_scan_at FROM domains WHERE id = $1`
		if err := pc.Pool.QueryRow(ctx, q, id).Scan(&last, &next); err != nil {
			t.Fatalf("read stamps (%d): %v", id, err)
		}
		return last, next
	}

	t.Run("manual Force resets the cadence clock from the real scan", func(t *testing.T) {
		d := createDomain("manual.chokepoint.test")
		// Pre-seed a near-term cursor; a manual scan must push it a FULL daily
		// interval out, proving the clock resets from the actual scan, not the old
		// cursor.
		setNextScan(t, ctx, pc, d.ID, "1 hour")

		enqueue(d, DomainScanOptions{Force: true, Source: store.ScanSourceUserSupplied})

		last, next := stamps(d.ID)
		if !last.Valid || time.Since(last.Time) > time.Minute {
			t.Errorf("last_scanned_at = %v, want ~now", last)
		}
		if !next.Valid {
			t.Fatalf("next_scan_at not set after manual scan")
		}
		if delta := time.Until(next.Time); delta < 23*time.Hour || delta > 27*time.Hour {
			t.Errorf("next_scan_at in %v, want a full daily interval (~24-26h)", delta)
		}
	})

	t.Run("discovered scan enters the schedule", func(t *testing.T) {
		d := createDomain("discovered.chokepoint.test")
		enqueue(d, DomainScanOptions{
			Force: false, RecencyWindow: time.Hour, Source: store.ScanSourceDiscovered,
		})
		last, next := stamps(d.ID)
		if !last.Valid {
			t.Errorf("last_scanned_at not stamped for discovered scan")
		}
		if !next.Valid {
			t.Errorf("next_scan_at not set for discovered scan (domain didn't enter schedule)")
		}
	})

	t.Run("off domain is stamped but left out of the schedule", func(t *testing.T) {
		d := createDomain("off.chokepoint.test")
		setScanFrequency(t, ctx, pc, d.ID, store.ScanFrequencyOff)

		enqueue(d, DomainScanOptions{Force: true, Source: store.ScanSourceUserSupplied})

		last, next := stamps(d.ID)
		if !last.Valid {
			t.Errorf("last_scanned_at not stamped for off domain")
		}
		if next.Valid {
			t.Errorf("next_scan_at = %v for off domain, want NULL", next.Time)
		}
	})
}
