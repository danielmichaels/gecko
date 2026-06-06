package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/riverqueue/river"
)

// PurgeDNSCacheArgs drives the periodic deletion of expired dns_cache rows. River
// runs periodic jobs on the elected leader only, so a single instance purges on
// behalf of the whole fleet.
type PurgeDNSCacheArgs struct{}

func (PurgeDNSCacheArgs) Kind() string { return "purge_dns_cache" }

type PurgeDNSCacheWorker struct {
	river.WorkerDefaults[PurgeDNSCacheArgs]
	Logger slog.Logger
	Store  *store.Queries
}

func (w *PurgeDNSCacheWorker) Work(ctx context.Context, _ *river.Job[PurgeDNSCacheArgs]) error {
	start := time.Now()
	deleted, err := w.Store.DNSCachePurgeExpired(ctx)
	if err != nil {
		return fmt.Errorf("purge expired dns cache: %w", err)
	}
	w.Logger.InfoContext(
		ctx,
		"dns cache purge complete",
		"deleted", deleted,
		"duration", time.Since(start),
	)
	return nil
}
