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

func seedStatsSPF(
	t *testing.T,
	ctx context.Context,
	q *store.Queries,
	domainID int32,
	severity store.FindingSeverity,
) {
	t.Helper()
	if _, err := q.AssessCreateSPFFinding(ctx, store.AssessCreateSPFFindingParams{
		DomainID:  pgtype.Int4{Int32: domainID, Valid: true},
		Severity:  severity,
		Status:    store.FindingStatusOpen,
		IssueType: "missing_spf",
	}); err != nil {
		t.Fatalf("seed spf finding (domain %d): %v", domainID, err)
	}
}

// TestRefreshTenantStatsWorker_ComputesAndIsolatesTenants seeds records and
// findings across two tenants, runs the refresh, and asserts each tenant's
// cached rollups are correct and do not leak across the tenant boundary.
func TestRefreshTenantStatsWorker_ComputesAndIsolatesTenants(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	q := pc.Queries

	t1 := seedStatsTenant(t, ctx, q, "owner1@stats.test")
	t2 := seedStatsTenant(t, ctx, q, "owner2@stats.test")

	// Tenant 1: two domains. dCrit has 3 A records + a critical SPF finding;
	// dWarn has 1 A record + a medium SPF finding. Record total = 4, critical = 1,
	// warning = 1.
	dCrit := seedStatsDomain(t, ctx, q, t1, "crit.t1.test")
	dWarn := seedStatsDomain(t, ctx, q, t1, "warn.t1.test")
	seedStatsARecord(t, ctx, q, dCrit, "192.0.2.1")
	seedStatsARecord(t, ctx, q, dCrit, "192.0.2.2")
	seedStatsARecord(t, ctx, q, dCrit, "192.0.2.3")
	seedStatsARecord(t, ctx, q, dWarn, "192.0.2.4")
	seedStatsSPF(t, ctx, q, dCrit, store.FindingSeverityCritical)
	seedStatsSPF(t, ctx, q, dWarn, store.FindingSeverityMedium)

	// Tenant 2: one domain with 1 A record and no findings. Record total = 1,
	// critical = 0, warning = 0.
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

	// Re-running is idempotent: counts do not double.
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
