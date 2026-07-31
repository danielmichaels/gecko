package ui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// detectCheckKinds parses internal/detect for its Check* constants. The
// detectors own the check_kind vocabulary, so reading it from source is what
// stops the UI's label tables from silently falling behind a new detector.
func detectCheckKinds(t *testing.T) map[string]string {
	t.Helper()
	const dir = "../detect"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read internal/detect: %v", err)
	}

	fset := token.NewFileSet()
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 {
				return true
			}
			if !strings.HasPrefix(spec.Names[0].Name, "Check") {
				return true
			}
			lit, ok := spec.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			out[v] = name
			return true
		})
	}
	if len(out) == 0 {
		t.Fatal("found no Check* constants in internal/detect — parser is wrong")
	}
	return out
}

func TestFindingKindLabels_CoverEveryCheckKind(t *testing.T) {
	t.Parallel()
	kinds := detectCheckKinds(t)

	var missingLabel, missingShort, missingOrder []string
	for kind, path := range kinds {
		if strings.TrimSpace(findingKindLabels[kind]) == "" {
			missingLabel = append(missingLabel, kind+" ("+path+")")
		}
		if strings.TrimSpace(findingKindShort[kind]) == "" {
			missingShort = append(missingShort, kind+" ("+path+")")
		}
		if !slicesContains(findingKindOrder, kind) {
			missingOrder = append(missingOrder, kind+" ("+path+")")
		}
	}
	if len(missingLabel) > 0 {
		t.Errorf("check kinds with no dropdown label: %v", missingLabel)
	}
	if len(missingShort) > 0 {
		t.Errorf("check kinds with no row short code: %v", missingShort)
	}
	if len(missingOrder) > 0 {
		t.Errorf("check kinds missing from findingKindOrder: %v", missingOrder)
	}

	for _, kind := range findingKindOrder {
		if _, ok := kinds[kind]; !ok {
			t.Errorf("findingKindOrder lists %q, which no detector emits", kind)
		}
	}
}

// TestFindingKindShort_FitsRowColumn pins the constraint that actually broke:
// .fline reserves a fixed 64px mono track for the kind, so a long code overruns
// it and collides with the finding title.
func TestFindingKindShort_FitsRowColumn(t *testing.T) {
	t.Parallel()
	const maxRuneWidth = 10
	for kind, short := range findingKindShort {
		if n := len([]rune(short)); n > maxRuneWidth {
			t.Errorf(
				"short code for %q is %q (%d chars); the row column fits %d",
				kind, short, n, maxRuneWidth,
			)
		}
	}
}

func TestShortKind_FallsBackToRawValue(t *testing.T) {
	t.Parallel()
	if got := shortKind("email_security"); got != "EMAIL" {
		t.Errorf("shortKind(email_security) = %q, want EMAIL", got)
	}
	if got := shortKind("brand_new_check"); got != "brand_new_check" {
		t.Errorf("unmapped kind should render raw, got %q", got)
	}
}

func TestKindOptions_OrdersKnownKindsAndLabelsThem(t *testing.T) {
	t.Parallel()
	opts := kindOptions(map[string]int{
		"zone_transfer":  1,
		"email_security": 3,
		"caa":            2,
	})
	if len(opts) != 3 {
		t.Fatalf("want 3 options, got %d (%+v)", len(opts), opts)
	}
	if opts[0].Value != "email_security" {
		t.Errorf("want email_security first per findingKindOrder, got %q", opts[0].Value)
	}
	if opts[0].Label != "Email security" {
		t.Errorf("option label = %q, want a friendly label not the raw kind", opts[0].Label)
	}
	if opts[0].Count != 3 {
		t.Errorf("option count = %d, want 3", opts[0].Count)
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
