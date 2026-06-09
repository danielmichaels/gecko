package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
)

func seedCacheRow(t *testing.T, q *store.Queries, fqdn string, expiresAt time.Time) {
	t.Helper()
	if err := q.DNSCacheUpsert(context.Background(), store.DNSCacheUpsertParams{
		Qtype:     1,
		Fqdn:      fqdn,
		Answers:   []string{"192.0.2.1"},
		Status:    1,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}); err != nil {
		t.Fatalf("seed cache row %s: %v", fqdn, err)
	}
}

func TestPurgeDNSCacheWorker_DeletesOnlyExpiredRows(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	now := time.Now()
	seedCacheRow(t, pc.Queries, "expired-a.", now.Add(-time.Hour))
	seedCacheRow(t, pc.Queries, "expired-b.", now.Add(-time.Minute))
	seedCacheRow(t, pc.Queries, "fresh-a.", now.Add(time.Hour))
	seedCacheRow(t, pc.Queries, "fresh-b.", now.Add(time.Hour))

	w := &PurgeDNSCacheWorker{Logger: *testhelpers.TestLogger, Store: pc.Queries}
	if err := w.Work(ctx, &river.Job[PurgeDNSCacheArgs]{Args: PurgeDNSCacheArgs{}}); err != nil {
		t.Fatalf("worker Work: %v", err)
	}

	// Expired rows are gone: a follow-up purge finds nothing to delete.
	if n, err := pc.Queries.DNSCachePurgeExpired(ctx); err != nil || n != 0 {
		t.Fatalf("expected expired rows already purged (0 deleted), got n=%d err=%v", n, err)
	}
	// Fresh rows survived.
	if _, err := pc.Queries.DNSCacheGet(ctx, store.DNSCacheGetParams{Qtype: 1, Fqdn: "fresh-a."}); err != nil {
		t.Fatalf("expected fresh row to survive purge: %v", err)
	}
}
