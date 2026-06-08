package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/riverqueue/river"
)

// RefreshTenantStatsArgs drives the periodic recompute of the Domains list stat
// strip (record total + critical/warning domain counts) into tenant_stats. River
// runs periodic jobs on the elected leader only, so a single instance refreshes
// on behalf of the whole fleet. The aggregates are computed in two grouped passes
// over all tenants, keeping the cost off the request path.
type RefreshTenantStatsArgs struct{}

func (RefreshTenantStatsArgs) Kind() string { return "refresh_tenant_stats" }

type RefreshTenantStatsWorker struct {
	river.WorkerDefaults[RefreshTenantStatsArgs]
	Logger slog.Logger
	Store  *store.Queries
}

func (w *RefreshTenantStatsWorker) Work(
	ctx context.Context,
	_ *river.Job[RefreshTenantStatsArgs],
) error {
	start := time.Now()

	recordTotals, err := w.Store.TenantRecordTotalsAll(ctx)
	if err != nil {
		return fmt.Errorf("tenant record totals: %w", err)
	}
	findingStats, err := w.Store.TenantFindingStatsAll(ctx)
	if err != nil {
		return fmt.Errorf("tenant finding stats: %w", err)
	}

	type rollup struct {
		recordTotal   int64
		criticalCount int32
		warningCount  int32
	}
	merged := make(map[int32]*rollup)
	at := func(tenantID int32) *rollup {
		r, ok := merged[tenantID]
		if !ok {
			r = &rollup{}
			merged[tenantID] = r
		}
		return r
	}
	for _, rt := range recordTotals {
		if !rt.TenantID.Valid {
			continue
		}
		at(rt.TenantID.Int32).recordTotal = rt.Total
	}
	for _, fs := range findingStats {
		if !fs.TenantID.Valid {
			continue
		}
		r := at(fs.TenantID.Int32)
		r.criticalCount = fs.CriticalCount
		r.warningCount = fs.WarningCount
	}

	for tenantID, r := range merged {
		if err := w.Store.TenantStatsUpsert(ctx, store.TenantStatsUpsertParams{
			TenantID:      tenantID,
			RecordTotal:   r.recordTotal,
			CriticalCount: r.criticalCount,
			WarningCount:  r.warningCount,
		}); err != nil {
			return fmt.Errorf("upsert tenant stats (tenant %d): %w", tenantID, err)
		}
	}

	w.Logger.DebugContext(
		ctx,
		"tenant stats refresh complete",
		"tenants", len(merged),
		"duration", time.Since(start),
	)
	return nil
}
