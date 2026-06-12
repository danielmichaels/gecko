package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

func freqPtr(f store.ScanFrequency) *store.ScanFrequency { return &f }

// readNextScan reads a domain's raw next_scan_at by uid (DomainsGetByID does not
// project the scheduling columns).
func readNextScan(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	uid string,
) (time.Time, bool) {
	t.Helper()
	var ts struct {
		valid bool
		time  time.Time
	}
	row := pc.Pool.QueryRow(ctx, "SELECT next_scan_at FROM domains WHERE uid = $1", uid)
	var nt *time.Time
	if err := row.Scan(&nt); err != nil {
		t.Fatalf("read next_scan_at (%s): %v", uid, err)
	}
	if nt != nil {
		ts.valid, ts.time = true, *nt
	}
	return ts.time, ts.valid
}

func TestDomainsService_SetScanFrequency_ForbiddenForViewer(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	tid := createTenant(t, ctx, pc, "viewer@freq.test")
	d := seedDomain(t, ctx, pc, tid, "viewer.freq.test")
	svc := newTestService(pc, &fakeScheduler{})

	_, err = svc.DomainsService().
		SetScanFrequency(ctx, principalWithRole(tid, "viewer"), d.Uid, freqPtr(store.ScanFrequencyWeekly))
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("viewer SetScanFrequency err = %v, want ErrForbidden", err)
	}
}

func TestDomainsService_SetScanFrequency_OwnerRecomputes(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	tid := createTenant(t, ctx, pc, "owner@freq.test")
	d := seedDomain(t, ctx, pc, tid, "owner.freq.test")
	svc := newTestService(pc, &fakeScheduler{})
	owner := ownerPrincipal(tid)

	// Explicit weekly override: cursor ~7d out (within +10% jitter).
	dom, err := svc.DomainsService().
		SetScanFrequency(ctx, owner, d.Uid, freqPtr(store.ScanFrequencyWeekly))
	if err != nil {
		t.Fatalf("set weekly: %v", err)
	}
	if !dom.ScanFrequency.Valid || dom.ScanFrequency.ScanFrequency != store.ScanFrequencyWeekly {
		t.Errorf("override = %+v, want weekly", dom.ScanFrequency)
	}
	if !dom.NextScanAt.Valid {
		t.Fatalf("next_scan_at not set after weekly override")
	}
	if d := time.Until(dom.NextScanAt.Time); d < 167*time.Hour || d > 186*time.Hour {
		t.Errorf("weekly next_scan_at in %v, want ~168-185h", d)
	}

	// Off override: cursor cleared (paused).
	dom, err = svc.DomainsService().
		SetScanFrequency(ctx, owner, d.Uid, freqPtr(store.ScanFrequencyOff))
	if err != nil {
		t.Fatalf("set off: %v", err)
	}
	if dom.NextScanAt.Valid {
		t.Errorf("next_scan_at after off = %v, want NULL", dom.NextScanAt)
	}

	// Inherit (nil): with no tenant settings row the default falls back to daily,
	// so the cursor returns ~1d out and the stored override is NULL.
	dom, err = svc.DomainsService().SetScanFrequency(ctx, owner, d.Uid, nil)
	if err != nil {
		t.Fatalf("set inherit: %v", err)
	}
	if dom.ScanFrequency.Valid {
		t.Errorf("override after inherit = %+v, want NULL", dom.ScanFrequency)
	}
	if d := time.Until(dom.NextScanAt.Time); d < 23*time.Hour || d > 27*time.Hour {
		t.Errorf("inherited (daily) next_scan_at in %v, want ~24-26h", d)
	}
}

func TestDomainsService_SetScanFrequency_NotFound(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	tid := createTenant(t, ctx, pc, "nf@freq.test")
	svc := newTestService(pc, &fakeScheduler{})

	_, err = svc.DomainsService().
		SetScanFrequency(ctx, ownerPrincipal(tid), "domain_doesnotexist", freqPtr(store.ScanFrequencyDaily))
	if !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unknown uid err = %v, want ErrNotFound", err)
	}
}

func TestSettingsService_SetDefaultScanFrequency_ForbiddenForViewer(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	tid := createTenant(t, ctx, pc, "viewer@settings.test")
	svc := newTestService(pc, &fakeScheduler{})

	err = svc.SettingsService().
		SetDefaultScanFrequency(ctx, principalWithRole(tid, "viewer"), store.ScanFrequencyWeekly)
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("viewer SetDefaultScanFrequency err = %v, want ErrForbidden", err)
	}
}

func TestSettingsService_SetDefaultScanFrequency_RecomputesInheriting(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	tid := createTenant(t, ctx, pc, "owner@settings.test")
	svc := newTestService(pc, &fakeScheduler{})
	owner := ownerPrincipal(tid)

	inheriting := seedDomain(t, ctx, pc, tid, "inherit.settings.test")
	overridden := seedDomain(t, ctx, pc, tid, "override.settings.test")

	// Give the overridden domain an explicit weekly override (cursor ~7d).
	if _, err := svc.DomainsService().
		SetScanFrequency(ctx, owner, overridden.Uid, freqPtr(store.ScanFrequencyWeekly)); err != nil {
		t.Fatalf("seed override: %v", err)
	}
	overrideBefore, ok := readNextScan(t, ctx, pc, overridden.Uid)
	if !ok {
		t.Fatalf("override next_scan_at not set")
	}

	// Change the tenant default to hourly.
	if err := svc.SettingsService().
		SetDefaultScanFrequency(ctx, owner, store.ScanFrequencyHourly); err != nil {
		t.Fatalf("set default hourly: %v", err)
	}

	// Inheriting domain pulled in to ~1h.
	inh, ok := readNextScan(t, ctx, pc, inheriting.Uid)
	if !ok {
		t.Fatalf("inheriting next_scan_at not set after default change")
	}
	if d := time.Until(inh); d > 2*time.Hour {
		t.Errorf("inheriting next_scan_at in %v, want ~1h after hourly default", d)
	}

	// Overridden domain untouched by the default change.
	overrideAfter, _ := readNextScan(t, ctx, pc, overridden.Uid)
	if !overrideAfter.Equal(overrideBefore) {
		t.Errorf("overridden next_scan_at changed: %v -> %v", overrideBefore, overrideAfter)
	}

	// The default is persisted.
	got, err := svc.SettingsService().GetScanSettings(ctx, owner)
	if err != nil {
		t.Fatalf("get scan settings: %v", err)
	}
	if got != store.ScanFrequencyHourly {
		t.Errorf("default = %q, want hourly", got)
	}
}
