package server

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
)

// compressExceptSSE wraps chi's Compress middleware but lets Server-Sent Event
// requests through untouched. SSE handlers (datastar.NewSSE) commit their
// response header via an implicit flush rather than a Write/WriteHeader call,
// which desyncs compressResponseWriter's header bookkeeping and produces a
// spurious "superfluous response.WriteHeader call" once the first event writes.
// Bypassing the wrapper for event-stream requests avoids that entirely; gzip is
// useless on a streaming response anyway.
func compressExceptSSE(level int, types ...string) func(http.Handler) http.Handler {
	compressor := middleware.Compress(level, types...)
	return func(next http.Handler) http.Handler {
		compressed := compressor(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSSERequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			compressed.ServeHTTP(w, r)
		})
	}
}

func isSSERequest(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}
