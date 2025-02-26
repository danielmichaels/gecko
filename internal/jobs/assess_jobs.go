package jobs

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"

	"github.com/danielmichaels/gecko/internal/assessor"
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
	w.Logger.Info("assess CNAME started", "domain", job.Args.Domain)
	a := assessor.NewAssessor(assessor.Config{Logger: &w.Logger, Store: w.Store})
	a.AssessCNAMEDangling(job.Args.Domain)
	/* todo:
	- cloud provider checks
	- http/https checks
	- wildcard detection?
	- api checks?
	- custom error page detection
	*/
	return nil
}
