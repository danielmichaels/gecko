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

// setNextScan sets a domain's next_scan_at to now() + the given Postgres interval
// literal (e.g. "-1 hour", "30 minutes"), computed on the DB clock to avoid skew.
func setNextScan(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	id int32,
	offset string,
) {
	t.Helper()
	_, err := pc.Pool.Exec(
		ctx,
		"UPDATE domains SET next_scan_at = now() + $2::interval WHERE id = $1",
		id, offset,
	)
	if err != nil {
		t.Fatalf("set next_scan_at (domain %d): %v", id, err)
	}
}

// setScanFrequency sets a domain's per-domain override directly.
func setScanFrequency(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	id int32,
	freq store.ScanFrequency,
) {
	t.Helper()
	_, err := pc.Pool.Exec(ctx, "UPDATE domains SET scan_frequency = $2 WHERE id = $1", id, freq)
	if err != nil {
		t.Fatalf("set scan_frequency (domain %d): %v", id, err)
	}
}

// setInactive flips a domain to inactive.
func setInactive(t *testing.T, ctx context.Context, pc *testhelpers.PostgresContainer, id int32) {
	t.Helper()
	_, err := pc.Pool.Exec(ctx, "UPDATE domains SET status = 'inactive' WHERE id = $1", id)
	if err != nil {
		t.Fatalf("set inactive (domain %d): %v", id, err)
	}
}

func nextScanAt(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	id int32,
) pgtype.Timestamptz {
	t.Helper()
	const q = `SELECT next_scan_at FROM domains WHERE id = $1`
	var ts pgtype.Timestamptz
	if err := pc.Pool.QueryRow(ctx, q, id).Scan(&ts); err != nil {
		t.Fatalf("read next_scan_at (domain %d): %v", id, err)
	}
	return ts
}

// TestDomainsListDueForScan verifies the scheduler's hot query returns only
// active + due (non-NULL, <= now) domains, oldest-due first, respects the batch
// cap, and reports the effective frequency (override ?? tenant default).
func TestDomainsListDueForScan(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	tid := seedStatsTenant(t, ctx, q, "due@sched.test")
	if _, err := q.TenantSettingsUpsert(ctx, store.TenantSettingsUpsertParams{
		TenantID:             tid,
		DefaultScanFrequency: store.ScanFrequencyDaily,
	}); err != nil {
		t.Fatalf("upsert tenant settings: %v", err)
	}

	older := seedStatsDomain(t, ctx, q, tid, "older.due.test")   // due -2h, override weekly
	due := seedStatsDomain(t, ctx, q, tid, "due.test")           // due -1h, inherit (daily)
	future := seedStatsDomain(t, ctx, q, tid, "future.test")     // not due (+1h)
	inactive := seedStatsDomain(t, ctx, q, tid, "inactive.test") // inactive + due
	seedStatsDomain(t, ctx, q, tid, "off.test")                  // next_scan_at NULL -> excluded

	setNextScan(t, ctx, pc, older, "-2 hours")
	setScanFrequency(t, ctx, pc, older, store.ScanFrequencyWeekly)
	setNextScan(t, ctx, pc, due, "-1 hour")
	setNextScan(t, ctx, pc, future, "1 hour")
	setNextScan(t, ctx, pc, inactive, "-1 hour")
	setInactive(t, ctx, pc, inactive)
	// off keeps next_scan_at = NULL (the seed default)

	rows, err := q.DomainsListDueForScan(ctx, 10)
	if err != nil {
		t.Fatalf("DomainsListDueForScan: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("due rows = %d, want 2 (got %+v)", len(rows), rows)
	}
	// Ordered by next_scan_at ASC: older (-2h) before due (-1h).
	if rows[0].ID != older || rows[1].ID != due {
		t.Errorf("order = [%d, %d], want [%d, %d]", rows[0].ID, rows[1].ID, older, due)
	}
	if rows[0].EffectiveFrequency != store.ScanFrequencyWeekly {
		t.Errorf("older effective freq = %q, want weekly (override)", rows[0].EffectiveFrequency)
	}
	if rows[1].EffectiveFrequency != store.ScanFrequencyDaily {
		t.Errorf(
			"due effective freq = %q, want daily (inherited default)",
			rows[1].EffectiveFrequency,
		)
	}

	// Batch cap: limit 1 returns only the oldest-due domain.
	capped, err := q.DomainsListDueForScan(ctx, 1)
	if err != nil {
		t.Fatalf("DomainsListDueForScan(limit 1): %v", err)
	}
	if len(capped) != 1 || capped[0].ID != older {
		t.Errorf("capped = %+v, want single oldest-due domain %d", capped, older)
	}
}

// TestDomainsMarkScanned verifies the chokepoint stamp advances the cursor by the
// effective interval (within the ±10% jitter band) and clears it when paused.
func TestDomainsMarkScanned(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	tid := seedStatsTenant(t, ctx, q, "mark@sched.test")
	d := seedStatsDomain(t, ctx, q, tid, "mark.test")

	const base = 24 * 3600.0 // daily, in seconds
	if err := q.DomainsMarkScanned(ctx, store.DomainsMarkScannedParams{
		IsOff: false, BaseSecs: base, DomainID: d,
	}); err != nil {
		t.Fatalf("DomainsMarkScanned: %v", err)
	}

	// next_scan_at - last_scanned_at is the jitter expression with no clock skew
	// (both now() in one statement are identical): must land in [base, base*1.10).
	const deltaQ = `SELECT EXTRACT(EPOCH FROM (next_scan_at - last_scanned_at)) FROM domains WHERE id = $1`
	var deltaSecs float64
	if err := pc.Pool.QueryRow(ctx, deltaQ, d).Scan(&deltaSecs); err != nil {
		t.Fatalf("read stamp delta: %v", err)
	}
	if deltaSecs < base || deltaSecs >= base*1.10 {
		t.Errorf("next-last delta = %.0fs, want [%.0f, %.0f)", deltaSecs, base, base*1.10)
	}

	const lastQ = `SELECT last_scanned_at FROM domains WHERE id = $1`
	var lastScanned pgtype.Timestamptz
	if err := pc.Pool.QueryRow(ctx, lastQ, d).Scan(&lastScanned); err != nil {
		t.Fatalf("read last_scanned_at: %v", err)
	}
	if !lastScanned.Valid || time.Since(lastScanned.Time) > time.Minute {
		t.Errorf("last_scanned_at = %v, want ~now", lastScanned)
	}

	// Pausing (is_off) clears the cursor but still stamps last_scanned_at.
	if err := q.DomainsMarkScanned(ctx, store.DomainsMarkScannedParams{
		IsOff: true, BaseSecs: 0, DomainID: d,
	}); err != nil {
		t.Fatalf("DomainsMarkScanned (off): %v", err)
	}
	if ns := nextScanAt(t, ctx, pc, d); ns.Valid {
		t.Errorf("next_scan_at after pause = %v, want NULL", ns)
	}
}

// TestDomainsRecomputeNextScanByTenantDefault verifies a bulk default change
// recomputes only inheriting + active domains, leaving overrides and inactive
// domains untouched.
func TestDomainsRecomputeNextScanByTenantDefault(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	tid := seedStatsTenant(t, ctx, q, "recompute@sched.test")
	inheriting := seedStatsDomain(t, ctx, q, tid, "inherit.test")
	overridden := seedStatsDomain(t, ctx, q, tid, "override.test")
	inactiveInherit := seedStatsDomain(t, ctx, q, tid, "inactive-inherit.test")

	// Park all three far in the future so a recompute is observable as a change.
	setNextScan(t, ctx, pc, inheriting, "100 hours")
	setNextScan(t, ctx, pc, overridden, "100 hours")
	setScanFrequency(t, ctx, pc, overridden, store.ScanFrequencyWeekly)
	setNextScan(t, ctx, pc, inactiveInherit, "100 hours")
	setInactive(t, ctx, pc, inactiveInherit)

	overrideBefore := nextScanAt(t, ctx, pc, overridden)
	inactiveBefore := nextScanAt(t, ctx, pc, inactiveInherit)

	// New default: hourly.
	if err := q.DomainsRecomputeNextScanByTenantDefault(ctx, store.DomainsRecomputeNextScanByTenantDefaultParams{
		IsOff:    false,
		BaseSecs: 3600,
		TenantID: pgtype.Int4{Int32: tid, Valid: true},
	}); err != nil {
		t.Fatalf("recompute: %v", err)
	}

	// Inheriting active domain pulled in to ~1h (was 100h).
	inh := nextScanAt(t, ctx, pc, inheriting)
	if !inh.Valid || time.Until(inh.Time) > 2*time.Hour {
		t.Errorf("inheriting next_scan_at = %v, want ~1h ahead", inh.Time)
	}
	// Overridden domain untouched.
	if got := nextScanAt(t, ctx, pc, overridden); !got.Time.Equal(overrideBefore.Time) {
		t.Errorf("overridden next_scan_at changed: %v -> %v", overrideBefore.Time, got.Time)
	}
	// Inactive inheriting domain untouched.
	if got := nextScanAt(t, ctx, pc, inactiveInherit); !got.Time.Equal(inactiveBefore.Time) {
		t.Errorf("inactive next_scan_at changed: %v -> %v", inactiveBefore.Time, got.Time)
	}

	// Switching the default to off pauses inheriting domains (cursor NULL).
	if err := q.DomainsRecomputeNextScanByTenantDefault(ctx, store.DomainsRecomputeNextScanByTenantDefaultParams{
		IsOff:    true,
		BaseSecs: 0,
		TenantID: pgtype.Int4{Int32: tid, Valid: true},
	}); err != nil {
		t.Fatalf("recompute (off): %v", err)
	}
	if ns := nextScanAt(t, ctx, pc, inheriting); ns.Valid {
		t.Errorf("inheriting next_scan_at after off = %v, want NULL", ns)
	}
}

// TestDomainsGetScanFrequencies verifies the chokepoint's frequency read: it
// returns the override (NULL = inherit) and the tenant default, falling back to
// 'daily' when the tenant has no settings row.
func TestDomainsGetScanFrequencies(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	tid := seedStatsTenant(t, ctx, q, "freqs@sched.test")
	if _, err := q.TenantSettingsUpsert(ctx, store.TenantSettingsUpsertParams{
		TenantID: tid, DefaultScanFrequency: store.ScanFrequencySixHourly,
	}); err != nil {
		t.Fatalf("upsert settings: %v", err)
	}

	overridden := seedStatsDomain(t, ctx, q, tid, "ov.freqs.test")
	setScanFrequency(t, ctx, pc, overridden, store.ScanFrequencyWeekly)
	inheriting := seedStatsDomain(t, ctx, q, tid, "in.freqs.test")

	ov, err := q.DomainsGetScanFrequencies(ctx, overridden)
	if err != nil {
		t.Fatalf("get freqs (override): %v", err)
	}
	if !ov.ScanFrequency.Valid || ov.ScanFrequency.ScanFrequency != store.ScanFrequencyWeekly {
		t.Errorf("override = %+v, want weekly valid", ov.ScanFrequency)
	}
	if ov.DefaultScanFrequency != store.ScanFrequencySixHourly {
		t.Errorf("default = %q, want six_hourly", ov.DefaultScanFrequency)
	}

	inh, err := q.DomainsGetScanFrequencies(ctx, inheriting)
	if err != nil {
		t.Fatalf("get freqs (inherit): %v", err)
	}
	if inh.ScanFrequency.Valid {
		t.Errorf("inheriting override = %+v, want NULL", inh.ScanFrequency)
	}

	// Tenant with no settings row: default falls back to 'daily'.
	tid2 := seedStatsTenant(t, ctx, q, "nosettings@sched.test")
	d2 := seedStatsDomain(t, ctx, q, tid2, "ns.freqs.test")
	got, err := q.DomainsGetScanFrequencies(ctx, d2)
	if err != nil {
		t.Fatalf("get freqs (no settings): %v", err)
	}
	if got.DefaultScanFrequency != store.ScanFrequencyDaily {
		t.Errorf("fallback default = %q, want daily", got.DefaultScanFrequency)
	}
}

// TestTenantSettingsUpsertGet verifies the per-tenant settings round-trip and the
// no-row-yet contract.
func TestTenantSettingsUpsertGet(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	tid := seedStatsTenant(t, ctx, q, "settings@sched.test")

	if _, err := q.TenantSettingsGet(ctx, tid); err != pgx.ErrNoRows {
		t.Errorf("get before upsert err = %v, want pgx.ErrNoRows", err)
	}

	if _, err := q.TenantSettingsUpsert(ctx, store.TenantSettingsUpsertParams{
		TenantID: tid, DefaultScanFrequency: store.ScanFrequencyWeekly,
	}); err != nil {
		t.Fatalf("upsert weekly: %v", err)
	}
	got, err := q.TenantSettingsGet(ctx, tid)
	if err != nil {
		t.Fatalf("get after upsert: %v", err)
	}
	if got.DefaultScanFrequency != store.ScanFrequencyWeekly {
		t.Errorf("default = %q, want weekly", got.DefaultScanFrequency)
	}

	// Upsert again updates in place (one row per tenant).
	if _, err := q.TenantSettingsUpsert(ctx, store.TenantSettingsUpsertParams{
		TenantID: tid, DefaultScanFrequency: store.ScanFrequencyOff,
	}); err != nil {
		t.Fatalf("upsert off: %v", err)
	}
	got, err = q.TenantSettingsGet(ctx, tid)
	if err != nil {
		t.Fatalf("get after second upsert: %v", err)
	}
	if got.DefaultScanFrequency != store.ScanFrequencyOff {
		t.Errorf("default = %q, want off", got.DefaultScanFrequency)
	}
}
