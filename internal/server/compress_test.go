package server

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// compressibleBody is long, repetitive, and served as text/html so chi's
// compressor will actually gzip it when the middleware lets it through.
const compressibleBody = "<p>compress me</p>"

func newCompressibleHandler() http.Handler {
	body := strings.Repeat(compressibleBody, 256)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	})
}

func TestCompressExceptSSE_BypassesCompressionForEventStreamRequests(t *testing.T) {
	h := compressExceptSSE(5)(newCompressibleHandler())

	req := httptest.NewRequest(http.MethodGet, "/app/domains/x/timeline", nil)
	req.Header.Set("Accept", "text/event-stream, text/html, application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if got := rec.Result().Header.Get("Content-Encoding"); got != "" {
		t.Errorf("SSE request must bypass the compress wrapper, got Content-Encoding=%q", got)
	}
}

func TestCompressExceptSSE_CompressesNonSSERequests(t *testing.T) {
	h := compressExceptSSE(5)(newCompressibleHandler())

	req := httptest.NewRequest(http.MethodGet, "/app/domains", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if got := rec.Result().Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("non-SSE request should be gzip compressed, got Content-Encoding=%q", got)
	}
	gz, err := gzip.NewReader(rec.Result().Body)
	if err != nil {
		t.Fatalf("response body is not valid gzip: %v", err)
	}
	got, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("reading gzip body: %v", err)
	}
	if want := strings.Repeat(compressibleBody, 256); string(got) != want {
		t.Errorf("decompressed body mismatch: got %d bytes, want %d", len(got), len(want))
	}
}
