package jobs

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/danielmichaels/gecko/internal/mailer"
	"github.com/riverqueue/river"
)

// SendEmailArgs carries a fully-rendered email for asynchronous delivery. The
// body is rendered by the enqueuer so the worker stays a thin transport step;
// it runs on the default queue.
type SendEmailArgs struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	HTML    string `json:"html"`
	Text    string `json:"text"`
}

func (SendEmailArgs) Kind() string { return "send_email" }

type SendEmailWorker struct {
	river.WorkerDefaults[SendEmailArgs]
	Logger slog.Logger
	Mailer mailer.Mailer
}

func (w *SendEmailWorker) Work(ctx context.Context, job *river.Job[SendEmailArgs]) error {
	if err := w.Mailer.Send(ctx, mailer.Message{
		To:      job.Args.To,
		Subject: job.Args.Subject,
		HTML:    job.Args.HTML,
		Text:    job.Args.Text,
	}); err != nil {
		return fmt.Errorf("send email to %s: %w", job.Args.To, err)
	}
	return nil
}
