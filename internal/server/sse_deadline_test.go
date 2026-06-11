package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// deadlineBase is a ResponseWriter that records whether the per-connection
// deadline setters were reached — i.e. whether http.ResponseController could
// walk the wrapper chain all the way down to the real connection.
type deadlineBase struct {
	emptyResponseWriter
	wroteDeadline bool
	readDeadline  bool
}

func (d *deadlineBase) SetWriteDeadline(time.Time) error { d.wroteDeadline = true; return nil }
func (d *deadlineBase) SetReadDeadline(time.Time) error  { d.readDeadline = true; return nil }
func (d *deadlineBase) Flush()                           {}

// TestSSEDeadlineClearsThroughWrappers proves http.ResponseController can clear
// the read/write deadlines through the exact wrapper nesting an SSE handler sees
// in production: sseStatusRecorder -> chi WrapResponseWriter -> base. If any
// wrapper lacked Unwrap, the deadline clear would silently no-op and the server
// timeout would tear the long-lived stream down on a cycle.
func TestSSEDeadlineClearsThroughWrappers(t *testing.T) {
	base := &deadlineBase{}
	chiWrapped := middleware.NewWrapResponseWriter(base, 1)
	w := &sseStatusRecorder{ResponseWriter: chiWrapped}

	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("SetWriteDeadline through wrappers: %v", err)
	}
	if err := rc.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline through wrappers: %v", err)
	}
	if !base.wroteDeadline {
		t.Error("write deadline did not reach the base connection (broken Unwrap chain)")
	}
	if !base.readDeadline {
		t.Error("read deadline did not reach the base connection (broken Unwrap chain)")
	}
}

type emptyResponseWriter struct{}

func (emptyResponseWriter) Header() http.Header         { return http.Header{} }
func (emptyResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (emptyResponseWriter) WriteHeader(int)             {}
