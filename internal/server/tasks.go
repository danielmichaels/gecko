package server

import (
	"context"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
)

// scheduleDomainJobs schedules a scan and enumeration job for the given domain, if the domain is active.
// It uses a transaction to ensure the jobs are scheduled atomically.
func (app *Server) scheduleDomainJobs(ctx context.Context, domain store.Domains) error {
	if domain.Status != store.DomainStatusActive {
		// todo: trigger notification; inactive domains are not scanned
		return nil
	}
	tx, err := app.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	defer func(tx pgx.Tx, ctx context.Context) {
		_ = tx.Rollback(ctx)
	}(tx, ctx)

	// Schedule scan job
	_, err = app.RC.InsertTx(ctx, tx, jobs.ScanNewDomainArgs{
		Domain: domain.Name,
	}, nil)
	if err != nil {
		app.Log.Error("failed to schedule scan", "error", err, "domain", domain.Name, "domain_id", domain.Uid, "job_kind", jobs.ScanNewDomainArgs{}.Kind())
		return huma.Error500InternalServerError("failed to schedule scan", err)
	}

	// Schedule enumeration job
	_, err = app.RC.InsertTx(ctx, tx, jobs.EnumerateSubdomainArgs{
		Domain:      domain.Name,
		Concurrency: app.Conf.AppConf.EnumerationConcurrencyLimit,
	}, nil)
	if err != nil {
		app.Log.Error("failed to schedule scan", "error", err, "domain", domain.Name, "domain_id", domain.Uid, "job_kind", jobs.ScanNewDomainArgs{}.Kind())
		return huma.Error500InternalServerError("failed to schedule scan", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return huma.Error500InternalServerError("failed to commit transaction", err)
	}
	return nil
}
