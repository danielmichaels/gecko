package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

func scanCountBySource(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	domainID int32,
	source store.ScanSource,
) int {
	t.Helper()
	const q = `SELECT count(*) FROM scans WHERE domain_id = $1 AND source = $2`
	var n int
	if err := pc.Pool.QueryRow(ctx, q, domainID, source).Scan(&n); err != nil {
		t.Fatalf("count scans (domain %d): %v", domainID, err)
	}
	return n
}

// TestScheduledScanWorker_EnqueueDueScans verifies the worker enqueues a
// 'scheduled' scan for each due active domain, advances its cursor past now (so it
// drops out of the next tick), and never touches off or inactive domains — and
// that a back-to-back rerun does not double-enqueue.
func TestScheduledScanWorker_EnqueueDueScans(t *testing.T) {
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

	tid := seedStatsTenant(t, ctx, q, "worker@sched.test")
	if _, err := q.TenantSettingsUpsert(ctx, store.TenantSettingsUpsertParams{
		TenantID: tid, DefaultScanFrequency: store.ScanFrequencyDaily,
	}); err != nil {
		t.Fatalf("upsert settings: %v", err)
	}

	due := seedStatsDomain(t, ctx, q, tid, "due.worker.test")
	off := seedStatsDomain(t, ctx, q, tid, "off.worker.test")
	inactive := seedStatsDomain(t, ctx, q, tid, "inactive.worker.test")
	setNextScan(t, ctx, pc, due, "-1 hour")
	setNextScan(t, ctx, pc, inactive, "-1 hour")
	setInactive(t, ctx, pc, inactive)
	// off keeps next_scan_at NULL

	w := &ScheduledScanWorker{Logger: *testhelpers.TestLogger, Store: q, PgxPool: pc.Pool}

	n, err := w.EnqueueDueScans(ctx, rc)
	if err != nil {
		t.Fatalf("EnqueueDueScans: %v", err)
	}
	if n != 1 {
		t.Errorf("enqueued = %d, want 1 (only the due active domain)", n)
	}
	if got := scanCountBySource(t, ctx, pc, due, store.ScanSourceScheduled); got != 1 {
		t.Errorf("due domain scheduled scans = %d, want 1", got)
	}
	if got := scanCountBySource(t, ctx, pc, off, store.ScanSourceScheduled); got != 0 {
		t.Errorf("off domain scans = %d, want 0", got)
	}
	if got := scanCountBySource(t, ctx, pc, inactive, store.ScanSourceScheduled); got != 0 {
		t.Errorf("inactive domain scans = %d, want 0", got)
	}

	// The chokepoint advanced the cursor, so the domain is no longer due.
	if ns := nextScanAt(t, ctx, pc, due); !ns.Valid || !ns.Time.After(time.Now()) {
		t.Errorf("due domain next_scan_at = %v, want a future cursor", ns)
	}

	// Back-to-back rerun: nothing is due, so nothing is enqueued (no double-scan).
	n2, err := w.EnqueueDueScans(ctx, rc)
	if err != nil {
		t.Fatalf("EnqueueDueScans rerun: %v", err)
	}
	if n2 != 0 {
		t.Errorf("rerun enqueued = %d, want 0 (cursor advanced)", n2)
	}
	if got := scanCountBySource(t, ctx, pc, due, store.ScanSourceScheduled); got != 1 {
		t.Errorf("due domain scheduled scans after rerun = %d, want 1 (no double-enqueue)", got)
	}
}

// TestScheduledScanWorker_BatchCap verifies the per-tick batch cap bounds the
// fan-out; the remaining due domains are picked up on the next tick.
func TestScheduledScanWorker_BatchCap(t *testing.T) {
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

	tid := seedStatsTenant(t, ctx, q, "batch@sched.test")
	a := seedStatsDomain(t, ctx, q, tid, "a.batch.test")
	b := seedStatsDomain(t, ctx, q, tid, "b.batch.test")
	c := seedStatsDomain(t, ctx, q, tid, "c.batch.test")
	setNextScan(t, ctx, pc, a, "-3 hours")
	setNextScan(t, ctx, pc, b, "-2 hours")
	setNextScan(t, ctx, pc, c, "-1 hour")

	w := &ScheduledScanWorker{
		Logger:     *testhelpers.TestLogger,
		Store:      q,
		PgxPool:    pc.Pool,
		BatchLimit: 2,
	}

	n, err := w.EnqueueDueScans(ctx, rc)
	if err != nil {
		t.Fatalf("EnqueueDueScans: %v", err)
	}
	if n != 2 {
		t.Fatalf("first tick enqueued = %d, want 2 (batch cap)", n)
	}

	// The two oldest-due (a, b) were scanned; c remains due for the next tick.
	n2, err := w.EnqueueDueScans(ctx, rc)
	if err != nil {
		t.Fatalf("EnqueueDueScans tick 2: %v", err)
	}
	if n2 != 1 {
		t.Errorf("second tick enqueued = %d, want 1 (the remaining due domain)", n2)
	}
	if got := scanCountBySource(t, ctx, pc, c, store.ScanSourceScheduled); got != 1 {
		t.Errorf("domain c scheduled scans = %d, want 1", got)
	}
}
