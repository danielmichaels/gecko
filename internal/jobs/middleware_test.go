package jobs

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/riverqueue/river/rivertype"
)

type captureHandler struct {
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler       { return h }

func attrsOf(r slog.Record) map[string]slog.Value {
	m := make(map[string]slog.Value, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value
		return true
	})
	return m
}

func newTimingMiddleware() (*TimingMiddleware, *captureHandler) {
	h := &captureHandler{}
	return &TimingMiddleware{Logger: slog.New(h)}, h
}

func TestTimingMiddleware_LogsSuccessAtInfo(t *testing.T) {
	mw, h := newTimingMiddleware()
	job := &rivertype.JobRow{
		ID:          42,
		Kind:        "scan_certificate",
		Queue:       queueScanner,
		Attempt:     1,
		MaxAttempts: 5,
	}

	err := mw.Work(context.Background(), job, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(h.records) != 1 {
		t.Fatalf("expected exactly 1 log record, got %d", len(h.records))
	}
	rec := h.records[0]
	if rec.Level != slog.LevelInfo {
		t.Errorf("expected level INFO, got %v", rec.Level)
	}
	if rec.Message != "job worked" {
		t.Errorf("expected message %q, got %q", "job worked", rec.Message)
	}

	attrs := attrsOf(rec)
	if got := attrs["kind"].String(); got != "scan_certificate" {
		t.Errorf("kind: expected scan_certificate, got %q", got)
	}
	if got := attrs["queue"].String(); got != queueScanner {
		t.Errorf("queue: expected %q, got %q", queueScanner, got)
	}
	if got := attrs["attempt"].Int64(); got != 1 {
		t.Errorf("attempt: expected 1, got %d", got)
	}
	if got := attrs["max_attempts"].Int64(); got != 5 {
		t.Errorf("max_attempts: expected 5, got %d", got)
	}
	if got := attrs["job_id"].Int64(); got != 42 {
		t.Errorf("job_id: expected 42, got %d", got)
	}
	if _, ok := attrs["duration_ms"]; !ok {
		t.Error("expected duration_ms attribute to be present")
	}
	if _, ok := attrs["error"]; ok {
		t.Error("did not expect error attribute on success")
	}
}

func TestTimingMiddleware_LogsErrorAtErrorAndPropagates(t *testing.T) {
	mw, h := newTimingMiddleware()
	job := &rivertype.JobRow{Kind: "scan_dnssec", Queue: queueScanner, Attempt: 2, MaxAttempts: 5}
	sentinel := errors.New("dnssec lookup failed")

	err := mw.Work(context.Background(), job, func(context.Context) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error to propagate, got %v", err)
	}

	if len(h.records) != 1 {
		t.Fatalf("expected exactly 1 log record, got %d", len(h.records))
	}
	rec := h.records[0]
	if rec.Level != slog.LevelError {
		t.Errorf("expected level ERROR, got %v", rec.Level)
	}
	attrs := attrsOf(rec)
	if got := attrs["error"].String(); got != sentinel.Error() {
		t.Errorf("error attr: expected %q, got %q", sentinel.Error(), got)
	}
}
