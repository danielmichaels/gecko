package ui

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A long-lived SSE response must survive past the server's ReadTimeout and
// WriteTimeout — both default to 5s here, and either one silently aborts the
// stream (write fails the next event; read cancels the request context). The
// stream handlers call clearStreamDeadlines to defeat both; this proves it.
func TestClearStreamDeadlinesSurvivesServerTimeouts(t *testing.T) {
	t.Parallel()

	const (
		serverTimeout = 200 * time.Millisecond
		tick          = 80 * time.Millisecond
		ticks         = 10
	)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		clearStreamDeadlines(w)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("ResponseWriter is not a Flusher")
			return
		}
		for i := 0; i < ticks; i++ {
			_, _ = fmt.Fprintf(w, "data: %d\n\n", i)
			flusher.Flush()
			time.Sleep(tick)
		}
	})

	srv := httptest.NewUnstartedServer(h)
	srv.Config.ReadTimeout = serverTimeout
	srv.Config.WriteTimeout = serverTimeout
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	got := 0
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data:") {
			got++
		}
	}
	// Events 0-2 land within the 200ms timeout window; receiving well past that
	// (>=6, i.e. up to ~480ms in) proves the connection was not torn down.
	if got < 6 {
		t.Fatalf("received %d events before the stream died; want >=6 (timeouts not cleared)", got)
	}
}

// A burst of events between ticks must collapse to a single refresh: many
// mark() calls yield exactly one take()==true, and an idle interval yields none.
func TestCoalescerCollapsesBurst(t *testing.T) {
	t.Parallel()
	var c coalescer

	if c.take() {
		t.Fatal("idle coalescer should not be pending")
	}

	c.mark()
	c.mark()
	c.mark()
	if !c.take() {
		t.Fatal("a marked coalescer should take once")
	}
	if c.take() {
		t.Fatal("a coalescer should not take twice without a new mark")
	}
}
