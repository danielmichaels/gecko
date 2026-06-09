package jobs

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// TimingMiddleware wraps every job worked across all queues, emitting a single
// structured log line carrying the job's identity, attempt, duration and outcome.
// It runs around Worker.Work without any worker needing to know about it.
// Successful runs log at DEBUG (they are noise at scale); failures log at ERROR.
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
	attrs = append(attrs, domainIdentityAttrs(job.EncodedArgs)...)

	level := slog.LevelDebug
	if err != nil {
		level = slog.LevelError
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	m.Logger.LogAttrs(ctx, level, "job worked", attrs...)

	return err
}

// domainIdentityAttrs best-effort decodes the embedded DomainJobArgs identity
// from a job's encoded args so the completion line says which domain/scan it
// worked on. Jobs without domain args (cache purge, tenant-stats refresh) decode
// to empty and contribute no attributes.
func domainIdentityAttrs(encodedArgs []byte) []slog.Attr {
	if len(encodedArgs) == 0 {
		return nil
	}
	var ident struct {
		DomainUID  string `json:"domain_uid"`
		DomainName string `json:"domain_name"`
		ScanID     int64  `json:"scan_id"`
	}
	if err := json.Unmarshal(encodedArgs, &ident); err != nil {
		return nil
	}
	var attrs []slog.Attr
	if ident.DomainName != "" {
		attrs = append(attrs, slog.String("domain", ident.DomainName))
	}
	if ident.DomainUID != "" {
		attrs = append(attrs, slog.String("domain_uid", ident.DomainUID))
	}
	if ident.ScanID != 0 {
		attrs = append(attrs, slog.Int64("scan_id", ident.ScanID))
	}
	return attrs
}
