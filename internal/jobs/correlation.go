package jobs

import (
	"context"
	"encoding/json"

	"github.com/danielmichaels/gecko/internal/tracing"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const metadataTraceIDKey = "trace_id"

// CorrelationInsertHook persists the context's trace ID onto a job's metadata at
// insertion time, allowing the correlation ID to survive the gap between the
// inserting goroutine and the worker that later runs the job.
type CorrelationInsertHook struct {
	river.HookDefaults
}

func (h *CorrelationInsertHook) InsertBegin(
	ctx context.Context,
	params *rivertype.JobInsertParams,
) error {
	traceID, ok := tracing.TraceIDFromContext(ctx)
	if !ok {
		return nil
	}

	md := map[string]any{}
	if len(params.Metadata) > 0 {
		if err := json.Unmarshal(params.Metadata, &md); err != nil {
			return err
		}
	}
	if _, exists := md[metadataTraceIDKey]; exists {
		return nil
	}

	md[metadataTraceIDKey] = traceID
	encoded, err := json.Marshal(md)
	if err != nil {
		return err
	}
	params.Metadata = encoded
	return nil
}

// CorrelationMiddleware restores the trace ID stamped onto a job's metadata back
// into the context before the worker runs, so every log line and any jobs the
// worker inserts inherit the same correlation ID.
type CorrelationMiddleware struct {
	river.WorkerMiddlewareDefaults
}

func (m *CorrelationMiddleware) Work(
	ctx context.Context,
	job *rivertype.JobRow,
	doInner func(context.Context) error,
) error {
	var md struct {
		TraceID string `json:"trace_id"`
	}
	if len(job.Metadata) > 0 {
		if err := json.Unmarshal(job.Metadata, &md); err != nil {
			return err
		}
	}
	if md.TraceID != "" {
		ctx = tracing.WithTraceID(ctx, md.TraceID)
	}
	return doInner(ctx)
}
