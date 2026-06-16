package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
)

// RefreshTenantStatsArgs drives the recompute of the Domains list stat strip
// (record total + critical/warning domain counts) into tenant_stats.
//
// TenantID == 0 refreshes every tenant in two grouped passes — the periodic
// safety-net path, run on the elected leader. TenantID > 0 refreshes a single
// tenant via the index-driven per-page aggregates — the event-driven path,
// enqueued when a tenant deletes a domain (the one change the grouped recompute
// can't self-heal, since the tenant may drop to zero).
type RefreshTenantStatsArgs struct {
	TenantID int32 `json:"tenant_id,omitempty"`
}

func (RefreshTenantStatsArgs) Kind() string { return "refresh_tenant_stats" }

// InsertOpts makes enqueues unique by args: a burst of deletes for one tenant
// collapses to a single pending refresh (and the periodic full pass never piles
// up on itself), so however many domains are deleted, the tenant's one
// tenant_stats row is written once.
func (RefreshTenantStatsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		UniqueOpts: river.UniqueOpts{ByArgs: true},
	}
}

type RefreshTenantStatsWorker struct {
	river.WorkerDefaults[RefreshTenantStatsArgs]
	Logger slog.Logger
	Store  *store.Queries
}

func (w *RefreshTenantStatsWorker) Work(
	ctx context.Context,
	job *river.Job[RefreshTenantStatsArgs],
) error {
	start := time.Now()
	if job.Args.TenantID > 0 {
		if err := w.refreshOne(ctx, job.Args.TenantID); err != nil {
			return err
		}
		w.Logger.DebugContext(
			ctx,
			"tenant stats refresh complete",
			"tenant", job.Args.TenantID,
			"duration", time.Since(start),
		)
		return nil
	}

	n, err := w.refreshAll(ctx)
	if err != nil {
		return err
	}
	w.Logger.DebugContext(
		ctx,
		"tenant stats refresh complete",
		"tenants", n,
		"duration", time.Since(start),
	)
	return nil
}

// refreshAll recomputes every tenant in two grouped passes over the whole fleet,
// merges the two result sets per tenant, and upserts each. A tenant present in
// neither pass (no records and no open findings) keeps its last-written row; the
// event-driven path covers the drop-to-zero case the grouped pass misses.
func (w *RefreshTenantStatsWorker) refreshAll(ctx context.Context) (int, error) {
	recordTotals, err := w.Store.TenantRecordTotalsAll(ctx)
	if err != nil {
		return 0, fmt.Errorf("tenant record totals: %w", err)
	}
	findingStats, err := w.Store.TenantFindingStatsAll(ctx)
	if err != nil {
		return 0, fmt.Errorf("tenant finding stats: %w", err)
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
			return 0, fmt.Errorf("upsert tenant stats (tenant %d): %w", tenantID, err)
		}
	}
	return len(merged), nil
}

// refreshOne recomputes a single tenant from the index-driven per-page aggregates
// over the tenant's own domain IDs. A tenant with no domains yields zeros — this
// is what makes the drop-to-zero case correct the instant the delete lands.
func (w *RefreshTenantStatsWorker) refreshOne(ctx context.Context, tenantID int32) error {
	ids, err := w.Store.DomainsIDsByTenantID(ctx, pgtype.Int4{Int32: tenantID, Valid: true})
	if err != nil {
		return fmt.Errorf("domain ids (tenant %d): %w", tenantID, err)
	}

	var recordTotal int64
	var critical, warning int32
	if len(ids) > 0 {
		counts, err := w.Store.DomainsListRecordCounts(ctx, ids)
		if err != nil {
			return fmt.Errorf("record counts (tenant %d): %w", tenantID, err)
		}
		for _, c := range counts {
			recordTotal += int64(c.RecordCount)
		}

		sums, err := w.Store.DomainsListFindingsSummary(ctx, store.DomainsListFindingsSummaryParams{
			TenantID:  tenantID,
			DomainIds: ids,
		})
		if err != nil {
			return fmt.Errorf("findings summary (tenant %d): %w", tenantID, err)
		}
		for _, s := range sums {
			switch {
			case s.SeverityRank <= 2:
				critical++
			case s.SeverityRank == 3 || s.SeverityRank == 4:
				warning++
			}
		}
	}

	if err := w.Store.TenantStatsUpsert(ctx, store.TenantStatsUpsertParams{
		TenantID:      tenantID,
		RecordTotal:   recordTotal,
		CriticalCount: critical,
		WarningCount:  warning,
	}); err != nil {
		return fmt.Errorf("upsert tenant stats (tenant %d): %w", tenantID, err)
	}
	return nil
}
