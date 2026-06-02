package server

import (
	"context"

	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
)

// scheduleUserDomainScan enqueues a scan for an already-written domain within the
// caller's transaction. It is used by the POST/PUT handlers, which are explicit
// user actions: Force bypasses the recency guard (a user-triggered rescan always
// runs) but NOT the active-status gate (an inactive domain is still not scanned),
// and enumeration is requested at the apex. The domain write and this enqueue
// share one transaction so a scheduling failure rolls the domain write back.
func (app *Server) scheduleUserDomainScan(
	ctx context.Context,
	tx pgx.Tx,
	st *store.Queries,
	target jobs.DomainScanTarget,
	source store.DomainSource,
) (int64, error) {
	return jobs.EnqueueDomainScan(ctx, app.RC, tx, st, target, jobs.DomainScanOptions{
		EnumerateSubdomains: true,
		Source:              source,
		Force:               true,
		RecencyWindow:       app.Conf.AppConf.ScanRecencyWindow,
		Concurrency:         app.Conf.AppConf.EnumerationConcurrencyLimit,
	})
}
