package templates_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/ui/templates"
)

func renderToast(t *testing.T, v templates.ToastView) string {
	t.Helper()
	var buf bytes.Buffer
	if err := templates.Toast(v).Render(context.Background(), &buf); err != nil {
		t.Fatalf("Toast render error: %v", err)
	}
	return buf.String()
}

func TestToastRendersContent(t *testing.T) {
	out := renderToast(t, templates.ToastView{
		ID:        "abc",
		Variant:   "ok",
		Tag:       "SCAN",
		Title:     "Rescan queued",
		Desc:      "altibox.no · enumerating",
		Timestamp: "14:32:07",
	})

	for _, want := range []string{"Rescan queued", "altibox.no · enumerating", "SCAN", "14:32:07"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in toast output", want)
		}
	}
	// Variant drives the colour class.
	if !strings.Contains(out, `class="toast ok"`) {
		t.Errorf("expected variant class 'toast ok' in output, got:\n%s", out)
	}
	// Unique element id so idiomorph appends rather than morphs.
	if !strings.Contains(out, `id="toast-abc"`) {
		t.Error("expected element id 'toast-abc' in output")
	}
}

func TestToastVariantIcons(t *testing.T) {
	cases := map[string]string{"ok": "✓", "crit": "⚠", "warn": "!", "info": "⟳"}
	for variant, icon := range cases {
		out := renderToast(t, templates.ToastView{ID: "x", Variant: variant, Title: "t"})
		if !strings.Contains(out, icon) {
			t.Errorf("variant %q: expected icon %q in output", variant, icon)
		}
	}
}

func TestToastDatastarBindings(t *testing.T) {
	out := renderToast(t, templates.ToastView{ID: "x", Variant: "ok", Title: "t"})

	// Auto-dismiss: animationend filtered to the progress keyframe removes the toast.
	if !strings.Contains(out, "data-on:animationend") {
		t.Error("expected data-on:animationend auto-dismiss binding")
	}
	if !strings.Contains(out, "toast-progress") {
		t.Error("expected reference to the 'toast-progress' animation name for filtering")
	}
	// Manual dismiss: close button removes the nearest toast.
	if !strings.Contains(out, "data-on:click") {
		t.Error("expected data-on:click dismiss binding on the close button")
	}
}

func TestToastOmitsEmptyDescription(t *testing.T) {
	out := renderToast(t, templates.ToastView{ID: "x", Variant: "info", Title: "Only a title"})
	if strings.Contains(out, `class="toast-desc"`) {
		t.Error("expected no description element when Desc is empty")
	}
}
