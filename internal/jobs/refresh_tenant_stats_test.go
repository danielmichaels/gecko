package jobs

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
)

func seedStatsTenant(t *testing.T, ctx context.Context, q *store.Queries, email string) int32 {
	t.Helper()
	tenant, err := q.TenantCreate(ctx, email)
	if err != nil {
		t.Fatalf("create tenant %s: %v", email, err)
	}
	return tenant.ID
}

func seedStatsDomain(
	t *testing.T,
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
	name string,
) int32 {
	t.Helper()
	d, err := q.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       name,
		DomainType: store.DomainTypeSubdomain,
		Source:     store.DomainSourceUserSupplied,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		t.Fatalf("seed domain %s: %v", name, err)
	}
	return d.ID
}

func seedStatsARecord(
	t *testing.T,
	ctx context.Context,
	q *store.Queries,
	domainID int32,
	ip string,
) {
	t.Helper()
	if _, err := q.RecordsCreateA(ctx, store.RecordsCreateAParams{
		DomainID:    pgtype.Int4{Int32: domainID, Valid: true},
		Ipv4Address: ip,
	}); err != nil {
		t.Fatalf("seed a record (domain %d): %v", domainID, err)
	}
}

func seedStatsFinding(
	t *testing.T,
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
	domainName, severity string,
) {
	t.Helper()
	domain, err := q.DomainsGetByName(ctx, store.DomainsGetByNameParams{
		TenantID: pgtype.Int4{Int32: tenantID, Valid: true},
		Name:     domainName,
	})
	if err != nil {
		t.Fatalf("seed finding: lookup domain (%s): %v", domainName, err)
	}
	asset, err := q.AssetsUpsertDomain(ctx, store.AssetsUpsertDomainParams{
		TenantID: tenantID,
		Value:    domainName,
		DomainID: pgtype.Int4{Int32: domain.ID, Valid: true},
		Source:   "discovered",
	})
	if err != nil {
		t.Fatalf("seed finding: upsert asset (%s): %v", domainName, err)
	}
	if _, err := q.FindingsUpsert(ctx, store.FindingsUpsertParams{
		TenantID:  tenantID,
		AssetID:   asset.ID,
		CheckKind: "email_security",
		IssueType: "missing_spf",
		Severity:  severity,
		Title:     "missing_spf",
		Details:   "missing_spf",
	}); err != nil {
		t.Fatalf("seed finding (%s): %v", domainName, err)
	}
}

func TestRefreshTenantStatsWorker_ComputesAndIsolatesTenants(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	q := pc.Queries

	t1 := seedStatsTenant(t, ctx, q, "owner1@stats.test")
	t2 := seedStatsTenant(t, ctx, q, "owner2@stats.test")

	dCrit := seedStatsDomain(t, ctx, q, t1, "crit.t1.test")
	dWarn := seedStatsDomain(t, ctx, q, t1, "warn.t1.test")
	seedStatsARecord(t, ctx, q, dCrit, "192.0.2.1")
	seedStatsARecord(t, ctx, q, dCrit, "192.0.2.2")
	seedStatsARecord(t, ctx, q, dCrit, "192.0.2.3")
	seedStatsARecord(t, ctx, q, dWarn, "192.0.2.4")
	seedStatsFinding(t, ctx, q, t1, "crit.t1.test", "critical")
	seedStatsFinding(t, ctx, q, t1, "warn.t1.test", "medium")

	dOther := seedStatsDomain(t, ctx, q, t2, "only.t2.test")
	seedStatsARecord(t, ctx, q, dOther, "198.51.100.1")

	w := &RefreshTenantStatsWorker{Logger: *testhelpers.TestLogger, Store: q}
	if err := w.Work(ctx, &river.Job[RefreshTenantStatsArgs]{Args: RefreshTenantStatsArgs{}}); err != nil {
		t.Fatalf("worker Work: %v", err)
	}

	s1, err := q.TenantStatsGet(ctx, t1)
	if err != nil {
		t.Fatalf("get tenant 1 stats: %v", err)
	}
	if s1.RecordTotal != 4 {
		t.Errorf("tenant 1 record_total = %d, want 4", s1.RecordTotal)
	}
	if s1.CriticalCount != 1 {
		t.Errorf("tenant 1 critical_count = %d, want 1", s1.CriticalCount)
	}
	if s1.WarningCount != 1 {
		t.Errorf("tenant 1 warning_count = %d, want 1", s1.WarningCount)
	}

	s2, err := q.TenantStatsGet(ctx, t2)
	if err != nil {
		t.Fatalf("get tenant 2 stats: %v", err)
	}
	if s2.RecordTotal != 1 {
		t.Errorf("tenant 2 record_total = %d, want 1", s2.RecordTotal)
	}
	if s2.CriticalCount != 0 || s2.WarningCount != 0 {
		t.Errorf(
			"tenant 2 finding counts = (%d, %d), want (0, 0)",
			s2.CriticalCount,
			s2.WarningCount,
		)
	}

	if err := w.Work(ctx, &river.Job[RefreshTenantStatsArgs]{Args: RefreshTenantStatsArgs{}}); err != nil {
		t.Fatalf("worker Work (rerun): %v", err)
	}
	s1again, err := q.TenantStatsGet(ctx, t1)
	if err != nil {
		t.Fatalf("get tenant 1 stats (rerun): %v", err)
	}
	if s1again.RecordTotal != 4 {
		t.Errorf("tenant 1 record_total after rerun = %d, want 4", s1again.RecordTotal)
	}
}

func TestRefreshTenantStatsWorker_SingleTenant(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	q := pc.Queries
	w := &RefreshTenantStatsWorker{Logger: *testhelpers.TestLogger, Store: q}
	run := func(tenantID int32) {
		t.Helper()
		if err := w.Work(ctx, &river.Job[RefreshTenantStatsArgs]{
			Args: RefreshTenantStatsArgs{TenantID: tenantID},
		}); err != nil {
			t.Fatalf("worker Work (tenant %d): %v", tenantID, err)
		}
	}

	tid := seedStatsTenant(t, ctx, q, "single@stats.test")
	d := seedStatsDomain(t, ctx, q, tid, "d.single.test")
	seedStatsARecord(t, ctx, q, d, "192.0.2.10")
	seedStatsARecord(t, ctx, q, d, "192.0.2.11")
	seedStatsFinding(t, ctx, q, tid, "d.single.test", "critical")

	run(tid)

	s, err := q.TenantStatsGet(ctx, tid)
	if err != nil {
		t.Fatalf("get tenant stats: %v", err)
	}
	if s.RecordTotal != 2 || s.CriticalCount != 1 || s.WarningCount != 0 {
		t.Errorf(
			"stats = (records %d, crit %d, warn %d), want (2, 1, 0)",
			s.RecordTotal, s.CriticalCount, s.WarningCount,
		)
	}

	if _, err := pc.Pool.Exec(ctx, "DELETE FROM domains WHERE tenant_id = $1", tid); err != nil {
		t.Fatalf("delete domains: %v", err)
	}

	run(tid)

	z, err := q.TenantStatsGet(ctx, tid)
	if err != nil {
		t.Fatalf("get tenant stats (after delete): %v", err)
	}
	if z.RecordTotal != 0 || z.CriticalCount != 0 || z.WarningCount != 0 {
		t.Errorf(
			"stats after delete-to-zero = (records %d, crit %d, warn %d), want (0, 0, 0)",
			z.RecordTotal, z.CriticalCount, z.WarningCount,
		)
	}
}
