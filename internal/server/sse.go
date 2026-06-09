package server

import "net/http"

// recordSSEStatus makes the request logger record an accurate 200 for
// Server-Sent Event streams. datastar.NewSSE commits the response header via an
// http.ResponseController flush rather than WriteHeader; chi's flush-aware
// wrapper marks the response written but never captures a status code, so
// httplog logs the stream as "Response: 0" at WARN. Wrapping the writer so the
// first flush or write routes a WriteHeader(200) through the logging wrapper
// restores the real status. Must be registered inside (after) the logging
// middleware so it wraps that middleware's response writer.
func recordSSEStatus(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSSERequest(r) {
			w = &sseStatusRecorder{ResponseWriter: w}
		}
		next.ServeHTTP(w, r)
	})
}

type sseStatusRecorder struct {
	http.ResponseWriter
	wroteHeader bool
}

func (s *sseStatusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *sseStatusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

func (s *sseStatusRecorder) Flush() {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *sseStatusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}
