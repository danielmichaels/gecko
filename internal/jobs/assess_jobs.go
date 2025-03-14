package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/assessor"
	"github.com/danielmichaels/gecko/internal/tracing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/riverqueue/river"
)

type AssessCNAMEDanglingArgs struct {
	Domain string `json:"domain"`
}

func (AssessCNAMEDanglingArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessCNAMEDanglingArgs) Kind() string { return "assess_cname_dangling" }

type AssessCNAMEDanglingWorker struct {
	river.WorkerDefaults[AssessCNAMEDanglingArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *AssessCNAMEDanglingWorker) Work(
	ctx context.Context,
	job *river.Job[AssessCNAMEDanglingArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	w.Logger.InfoContext(ctx, "assess CNAME started", "domain", job.Args.Domain)
	_ = assessor.NewAssessor(assessor.Config{
		Logger: &w.Logger,
		Store:  w.Store,
	})
	/* todo:
	- cloud provider checks
	- http/https checks
	- wildcard detection?
	- api checks?
	- custom error page detection
	*/
	return nil
}

type AssessZoneTransferArgs struct {
	DomainUID string `json:"domain_uid"`
}

func (AssessZoneTransferArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessZoneTransferArgs) Kind() string { return "assess_zone_transfer" }

type AssessZoneTransferWorker struct {
	river.WorkerDefaults[AssessZoneTransferArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *AssessZoneTransferWorker) Work(
	ctx context.Context,
	job *river.Job[AssessZoneTransferArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess zone transfer started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger: &w.Logger,
		Store:  w.Store,
	})
	err := a.AssessZoneTransfer(ctx, job.Args.DomainUID)
	if err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess zone transfer complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}

type AssessEmailSecurityArgs struct {
	DomainUID string `json:"domain_uid"`
	DomainID  int    `json:"domain_id"`
}

func (AssessEmailSecurityArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessEmailSecurityArgs) Kind() string { return "assess_email_security" }

type AssessEmailSecurityWorker struct {
	river.WorkerDefaults[AssessEmailSecurityArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *AssessEmailSecurityWorker) Work(
	ctx context.Context,
	job *river.Job[AssessEmailSecurityArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess email security started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger: &w.Logger,
		Store:  w.Store,
	})
	err := a.AssessEmailSecurity(ctx, job.Args.DomainID)
	if err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess email security complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}
