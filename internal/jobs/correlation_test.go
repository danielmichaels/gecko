package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/danielmichaels/gecko/internal/tracing"
	"github.com/riverqueue/river/rivertype"
)

func TestCorrelationInsertHook_StampsTraceIDFromContext(t *testing.T) {
	hook := &CorrelationInsertHook{}
	ctx := tracing.WithTraceID(context.Background(), "trace-xyz")
	params := &rivertype.JobInsertParams{}

	if err := hook.InsertBegin(ctx, params); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	md := map[string]any{}
	if err := json.Unmarshal(params.Metadata, &md); err != nil {
		t.Fatalf("metadata is not valid json: %v", err)
	}
	if md["trace_id"] != "trace-xyz" {
		t.Errorf("expected trace_id trace-xyz, got %v", md["trace_id"])
	}
}

func TestCorrelationInsertHook_NoTraceIDLeavesMetadataNil(t *testing.T) {
	hook := &CorrelationInsertHook{}
	params := &rivertype.JobInsertParams{}

	if err := hook.InsertBegin(context.Background(), params); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if params.Metadata != nil {
		t.Errorf("expected nil metadata, got %s", params.Metadata)
	}
}

func TestCorrelationInsertHook_PreservesExistingMetadata(t *testing.T) {
	hook := &CorrelationInsertHook{}
	ctx := tracing.WithTraceID(context.Background(), "trace-xyz")
	params := &rivertype.JobInsertParams{Metadata: []byte(`{"output":"keep"}`)}

	if err := hook.InsertBegin(ctx, params); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	md := map[string]any{}
	if err := json.Unmarshal(params.Metadata, &md); err != nil {
		t.Fatalf("metadata is not valid json: %v", err)
	}
	if md["output"] != "keep" {
		t.Errorf("existing metadata key lost: %v", md)
	}
	if md["trace_id"] != "trace-xyz" {
		t.Errorf("expected trace_id to be added, got %v", md)
	}
}

// The full propagation contract: an initiator's trace id must survive insert ->
// worker pickup -> the worker's own trace handling -> any child job it enqueues.
// This is the end-to-end guarantee; it fails if a worker regenerates the trace
// (WithNewTraceID regenerate=true) instead of inheriting it.
func TestTracePropagatesFromInitiatorThroughWorkerToChild(t *testing.T) {
	hook := &CorrelationInsertHook{}
	mw := &CorrelationMiddleware{}

	// Initiator stamps its trace onto the parent job's metadata.
	initiatorCtx := tracing.WithTraceID(context.Background(), "trace-root")
	parent := &rivertype.JobInsertParams{}
	if err := hook.InsertBegin(initiatorCtx, parent); err != nil {
		t.Fatalf("stamp parent: %v", err)
	}

	// Worker picks up the parent and enqueues a child exactly as the real Work
	// methods do: middleware restores the trace, the worker keeps it
	// (WithNewTraceID regenerate=false), then inserts a child.
	parentJob := &rivertype.JobRow{Metadata: parent.Metadata}
	child := &rivertype.JobInsertParams{}
	err := mw.Work(context.Background(), parentJob, func(ctx context.Context) error {
		ctx = tracing.WithNewTraceID(ctx, false)
		return hook.InsertBegin(ctx, child)
	})
	if err != nil {
		t.Fatalf("worker: %v", err)
	}

	var md struct {
		TraceID string `json:"trace_id"`
	}
	if err := json.Unmarshal(child.Metadata, &md); err != nil {
		t.Fatalf("child metadata: %v", err)
	}
	if md.TraceID != "trace-root" {
		t.Errorf(
			"child trace_id = %q, want trace-root (trace must propagate, not regenerate)",
			md.TraceID,
		)
	}
}

func TestCorrelationMiddleware_RestoresTraceIDIntoContext(t *testing.T) {
	mw := &CorrelationMiddleware{}
	job := &rivertype.JobRow{Metadata: []byte(`{"trace_id":"trace-xyz"}`)}

	var seen string
	var ok bool
	err := mw.Work(context.Background(), job, func(ctx context.Context) error {
		seen, ok = tracing.TraceIDFromContext(ctx)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || seen != "trace-xyz" {
		t.Errorf("expected trace-xyz in inner ctx, got %q (ok=%v)", seen, ok)
	}
}

func TestCorrelationMiddleware_NoMetadataTraceIDLeavesContextClean(t *testing.T) {
	mw := &CorrelationMiddleware{}
	job := &rivertype.JobRow{Metadata: []byte(`{}`)}

	err := mw.Work(context.Background(), job, func(ctx context.Context) error {
		if _, ok := tracing.TraceIDFromContext(ctx); ok {
			t.Error("did not expect a trace ID in context")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCorrelationMiddleware_PropagatesInnerError(t *testing.T) {
	mw := &CorrelationMiddleware{}
	job := &rivertype.JobRow{Metadata: []byte(`{"trace_id":"x"}`)}
	sentinel := errors.New("inner failed")

	err := mw.Work(context.Background(), job, func(context.Context) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel to propagate, got %v", err)
	}
}
