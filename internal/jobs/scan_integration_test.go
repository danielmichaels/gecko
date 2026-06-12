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

// TestEnqueueDomainScan locks in the Phase 1 orchestration guard invariants: the
// active-status gate (Force never bypasses it), the leaf-job fan-out, and the
// recency dedup for discovered scans (which Force does bypass).
func TestEnqueueDomainScan(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	rc, err := New(ctx, Config{
		PgxPool: pc.Pool,
		Logger:  testhelpers.TestLogger,
		Store:   pc.Queries,
	})
	if err != nil {
		t.Fatalf("failed to create river client: %v", err)
	}

	const tenantID = int32(1) // seeded by test-data.sql

	countJobs := func(name string) int {
		var n int
		if err := pc.Pool.QueryRow(
			ctx,
			`SELECT count(*) FROM river_job WHERE args->>'domain_name' = $1`, name,
		).Scan(&n); err != nil {
			t.Fatalf("count jobs: %v", err)
		}
		return n
	}
	countScans := func(name string) int {
		var n int
		if err := pc.Pool.QueryRow(
			ctx,
			`SELECT count(*) FROM scans WHERE tenant_id=$1 AND domain_name=$2`, tenantID, name,
		).Scan(&n); err != nil {
			t.Fatalf("count scans: %v", err)
		}
		return n
	}
	createDomain := func(name string, status store.DomainStatus) store.DomainsInsertRow {
		d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
			TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
			Name:       name,
			DomainType: store.DomainTypeSubdomain,
			Source:     store.DomainSourceUserSupplied,
			Status:     status,
		})
		if err != nil {
			t.Fatalf("create domain %q: %v", name, err)
		}
		return d
	}
	enqueue := func(d store.DomainsInsertRow, opts DomainScanOptions) int64 {
		tx, err := pc.Pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		st := pc.Queries.WithTx(tx)
		scanID, err := EnqueueDomainScan(ctx, rc, tx, st, DomainScanTarget{
			TenantID:   tenantID,
			DomainID:   d.ID,
			DomainUID:  d.Uid,
			DomainName: d.Name,
			Status:     d.Status,
		}, opts)
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("EnqueueDomainScan: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		return scanID
	}

	t.Run("inactive domain is not scanned even with Force", func(t *testing.T) {
		d := createDomain("inactive.example.com", store.DomainStatusInactive)
		scanID := enqueue(d, DomainScanOptions{
			Force:               true,
			EnumerateSubdomains: true,
			Source:              store.ScanSourceUserSupplied,
		})
		if scanID != 0 {
			t.Errorf("scanID=%d, want 0 (active-status gate)", scanID)
		}
		if got := countScans(d.Name); got != 0 {
			t.Errorf("scans=%d, want 0", got)
		}
		if got := countJobs(d.Name); got != 0 {
			t.Errorf("jobs=%d, want 0", got)
		}
	})

	t.Run("active domain with Force creates a scan and 5 leaf jobs", func(t *testing.T) {
		d := createDomain("active.example.com", store.DomainStatusActive)
		scanID := enqueue(d, DomainScanOptions{
			Force:               true,
			EnumerateSubdomains: false,
			Source:              store.ScanSourceUserSupplied,
		})
		if scanID == 0 {
			t.Fatal("scanID=0, want >0")
		}
		if got := countScans(d.Name); got != 1 {
			t.Errorf("scans=%d, want 1", got)
		}
		if got := countJobs(d.Name); got != 5 {
			t.Errorf("jobs=%d, want 5 leaf jobs", got)
		}
	})

	t.Run("EnumerateSubdomains adds the enumeration job", func(t *testing.T) {
		d := createDomain("enum.example.com", store.DomainStatusActive)
		_ = enqueue(d, DomainScanOptions{
			Force:               true,
			EnumerateSubdomains: true,
			Source:              store.ScanSourceUserSupplied,
		})
		if got := countJobs(d.Name); got != 6 {
			t.Errorf("jobs=%d, want 6 (5 leaf + enumerate)", got)
		}
	})

	t.Run("recency guard dedupes discovered scans; Force bypasses", func(t *testing.T) {
		d := createDomain("recent.example.com", store.DomainStatusActive)
		first := enqueue(d, DomainScanOptions{
			Force:         false,
			RecencyWindow: time.Hour,
			Source:        store.ScanSourceDiscovered,
		})
		if first == 0 {
			t.Fatal("first discovered scan should run")
		}
		second := enqueue(d, DomainScanOptions{
			Force:         false,
			RecencyWindow: time.Hour,
			Source:        store.ScanSourceDiscovered,
		})
		if second != 0 {
			t.Errorf("second discovered scan within window should be skipped, got %d", second)
		}
		forced := enqueue(d, DomainScanOptions{
			Force:         true,
			RecencyWindow: time.Hour,
			Source:        store.ScanSourceUserSupplied,
		})
		if forced == 0 {
			t.Error("forced scan should bypass the recency window")
		}
		if got := countScans(d.Name); got != 2 {
			t.Errorf("scans=%d, want 2 (first discovered + forced)", got)
		}
	})
}
