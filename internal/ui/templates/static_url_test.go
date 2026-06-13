package templates

import (
	"strings"
	"testing"
)

func TestStaticURLAppendsContentHash(t *testing.T) {
	got := staticURL("/static/app.css")
	prefix := "/static/app.css?v="
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("expected cache-busted url with prefix %q, got %q", prefix, got)
	}
	if v := strings.TrimPrefix(got, prefix); v == "" {
		t.Fatalf("expected a non-empty content hash, got %q", got)
	}
	if again := staticURL("/static/app.css"); again != got {
		t.Fatalf("expected stable url across calls, got %q then %q", got, again)
	}
}

func TestStaticURLLeavesMissingFileUnchanged(t *testing.T) {
	const path = "/static/does-not-exist.css"
	if got := staticURL(path); got != path {
		t.Fatalf("expected %q unchanged for a missing asset, got %q", path, got)
	}
}
