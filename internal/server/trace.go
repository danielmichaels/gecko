package server

import (
	"net/http"

	"github.com/danielmichaels/gecko/internal/tracing"
)

// traceMiddleware seeds a correlation ID onto every inbound request's context so
// handler logs and any background jobs the request enqueues (via
// CorrelationInsertHook) share one trace ID. It inherits an existing trace ID if
// one is already present and mints a fresh one otherwise.
func traceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := tracing.WithNewTraceID(r.Context(), false)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
