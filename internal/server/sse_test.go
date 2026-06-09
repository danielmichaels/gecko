package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// statusProbe mimics chi's flushWriter: Flush() marks the response committed but
// never records a status code, so a handler that flushes before its first Write
// (datastar.NewSSE's pattern) leaves Status() at 0 — the artifact that makes
// httplog log SSE responses as "Response: 0" at WARN.
type statusProbe struct {
	header      http.Header
	status      int
	bytes       int
	wroteHeader bool
}

func (p *statusProbe) Header() http.Header {
	if p.header == nil {
		p.header = http.Header{}
	}
	return p.header
}

func (p *statusProbe) WriteHeader(code int) {
	if p.wroteHeader {
		return
	}
	p.status = code
	p.wroteHeader = true
}

func (p *statusProbe) Write(b []byte) (int, error) {
	if !p.wroteHeader {
		p.WriteHeader(http.StatusOK)
	}
	p.bytes += len(b)
	return len(b), nil
}

func (p *statusProbe) Flush() { p.wroteHeader = true }

// sseLikeHandler reproduces datastar.NewSSE: commit the response header by
// flushing, then stream an event.
func sseLikeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = http.NewResponseController(w).Flush()
		_, _ = io.WriteString(w, "data: hello\n\n")
	})
}

func sseRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/app/domains/x/timeline", nil)
	r.Header.Set("Accept", "text/event-stream")
	return r
}

func TestRecordSSEStatus_RecordsOKForFlushBeforeWrite(t *testing.T) {
	probe := &statusProbe{}

	recordSSEStatus(sseLikeHandler()).ServeHTTP(probe, sseRequest())

	if probe.status != http.StatusOK {
		t.Errorf("SSE response status should be recorded as 200, got %d", probe.status)
	}
	if probe.bytes == 0 {
		t.Error("expected SSE body bytes to be written through the recorder")
	}
}

func TestRecordSSEStatus_PassesNonSSEThrough(t *testing.T) {
	probe := &statusProbe{}
	var got http.ResponseWriter

	recordSSEStatus(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		got = w
	})).ServeHTTP(probe, httptest.NewRequest(http.MethodGet, "/app/domains", nil))

	if got != http.ResponseWriter(probe) {
		t.Errorf("non-SSE request should reach the handler unwrapped, got %T", got)
	}
}
