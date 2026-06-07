package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielmichaels/gecko/internal/tracing"
)

func TestTraceMiddleware_SeedsTraceIDIntoRequestContext(t *testing.T) {
	var got string
	var ok bool
	h := traceMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = tracing.TraceIDFromContext(r.Context())
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/app/domains", nil))

	if !ok || got == "" {
		t.Errorf("expected a non-empty trace id in request context, got %q (ok=%v)", got, ok)
	}
}

func TestTraceMiddleware_GivesEachRequestADistinctTraceID(t *testing.T) {
	var ids []string
	h := traceMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		id, _ := tracing.TraceIDFromContext(r.Context())
		ids = append(ids, id)
	}))

	for range 2 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if ids[0] == ids[1] {
		t.Errorf("expected distinct trace ids per request, both were %q", ids[0])
	}
}
