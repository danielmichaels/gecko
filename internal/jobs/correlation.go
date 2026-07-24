package jobs

import (
	"context"
	"encoding/json"

	"github.com/danielmichaels/gecko/internal/tracing"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const metadataTraceIDKey = "trace_id"

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
