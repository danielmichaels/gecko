package ui

import "testing"

// The global stylesheet defines `.disc{display:grid;width:16px}` as the timeline
// disclosure caret (see domains.templ `<span class="disc">▾</span>`). The Scans
// source badge/chip must NOT emit the bare "disc"/"user" tokens, or the caret rule
// clobbers them into a 16px grid square and the label overflows onto the next cell.
// These tests pin the source class to a namespaced, collision-free token.

func TestScanSourceClass_AvoidsDiscCaretCollision(t *testing.T) {
	cases := map[string]string{
		"discovered":    "src-disc",
		"user_supplied": "src-user",
	}
	for source, want := range cases {
		got := scanSourceClass(source)
		if got == "disc" || got == "user" {
			t.Errorf(
				"scanSourceClass(%q) = %q, collides with the global .disc/.user rule",
				source,
				got,
			)
		}
		if got != want {
			t.Errorf("scanSourceClass(%q) = %q, want %q", source, got, want)
		}
	}
}

func TestSourceOptions_EmitNamespacedClasses(t *testing.T) {
	opts := sourceOptions(map[string]int{"user_supplied": 2, "discovered": 1, "future_kind": 1})
	if len(opts) != 3 {
		t.Fatalf("sourceOptions returned %d options, want 3", len(opts))
	}
	for _, o := range opts {
		if o.Class == "disc" || o.Class == "user" {
			t.Errorf("source option %q has colliding class %q", o.Value, o.Class)
		}
	}
}
