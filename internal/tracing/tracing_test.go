package tracing

import (
	"context"
	"testing"
)

func TestWithTraceID_SetsRetrievableID(t *testing.T) {
	ctx := WithTraceID(context.Background(), "abc123")

	got, ok := TraceIDFromContext(ctx)
	if !ok {
		t.Fatal("expected trace ID to be present")
	}
	if got != "abc123" {
		t.Errorf("expected abc123, got %q", got)
	}
}

func TestTraceIDFromContext_AbsentWhenUnset(t *testing.T) {
	_, ok := TraceIDFromContext(context.Background())
	if ok {
		t.Error("expected no trace ID in empty context")
	}
}

func TestTraceIDFromContext_TreatsEmptyStringAsAbsent(t *testing.T) {
	ctx := WithTraceID(context.Background(), "")

	if _, ok := TraceIDFromContext(ctx); ok {
		t.Error("empty trace ID should be reported as absent")
	}
}
