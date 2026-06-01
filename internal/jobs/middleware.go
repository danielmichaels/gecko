package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// TimingMiddleware wraps every job worked across all queues, emitting a single
// structured log line carrying the job's identity, attempt, duration and outcome.
// It runs around Worker.Work without any worker needing to know about it.
type TimingMiddleware struct {
	river.WorkerMiddlewareDefaults
	Logger *slog.Logger
}

func (m *TimingMiddleware) Work(
	ctx context.Context,
	job *rivertype.JobRow,
	doInner func(context.Context) error,
) error {
	start := time.Now()
	err := doInner(ctx)

	attrs := []slog.Attr{
		slog.String("kind", job.Kind),
		slog.String("queue", job.Queue),
		slog.Int("attempt", job.Attempt),
		slog.Int("max_attempts", job.MaxAttempts),
		slog.Int64("job_id", job.ID),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
	}
	level := slog.LevelInfo
	if err != nil {
		level = slog.LevelError
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	m.Logger.LogAttrs(ctx, level, "job worked", attrs...)

	return err
}
