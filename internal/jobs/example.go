package jobs

import (
	"context"
	"github.com/danielmichaels/doublestag/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
	"log/slog"
)

type SendEmailArgs struct {
	To      string `json:"to"`
	From    string `json:"from"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func (SendEmailArgs) Kind() string { return "send_email" }

type SendEmailWorker struct {
	// Inject dependencies like an email service or logger here
	Logger slog.Logger
	DB     *store.Queries
	river.WorkerDefaults[SendEmailArgs]
}

func (w *SendEmailWorker) Work(ctx context.Context, job *river.Job[SendEmailArgs]) error {
	// example of using the database
	users, _ := w.DB.GetUsers(ctx, pgtype.Int4{Int32: 1, Valid: true})
	// example of using the logger
	w.Logger.Info("Got users", "users", users)
	w.Logger.Info("Sending email", "to", job.Args.To, "from", job.Args.From, "subject", job.Args.Subject)
	return nil
}
