package tracing

import (
	"context"

	"github.com/rs/xid"
)

type contextKey int

const (
	TraceCtxKey contextKey = iota + 1
)

// WithTraceID returns a context carrying the given trace ID. Used to restore a
// trace ID that was propagated out-of-band, such as via a job's metadata.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceCtxKey, traceID)
}

// TraceIDFromContext returns the trace ID held in ctx. An empty trace ID is
// reported as absent so callers can treat seeded-but-unset contexts uniformly.
func TraceIDFromContext(ctx context.Context) (string, bool) {
	traceID, ok := ctx.Value(TraceCtxKey).(string)
	if !ok || traceID == "" {
		return "", false
	}
	return traceID, true
}

// WithNewTraceID creates a new context with a unique trace ID if one does not already exist.
// If a trace ID already exists in the provided context, the original context is returned.
func WithNewTraceID(ctx context.Context, regenerate bool) context.Context {
	// Check if trace ID already exists
	if traceID, ok := ctx.Value(TraceCtxKey).(string); ok && traceID != "" && !regenerate {
		return ctx
	}
	// Create new trace ID if none exists
	guid := xid.New()
	return context.WithValue(ctx, TraceCtxKey, guid.String())
}
