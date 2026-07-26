package service_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

// detectIssueTypes parses internal/detect for its Issue* string constants. The
// detectors are the sole source of issue_type values, so this is what keeps the
// remediation catalogue honest without a hand-maintained list to drift.
func detectIssueTypes(t *testing.T) map[string]string {
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
			if !strings.HasPrefix(spec.Names[0].Name, "Issue") {
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
		t.Fatal("found no Issue* constants in internal/detect — parser is wrong")
	}
	return out
}

// TestFindingFixes_CoversEveryIssueType is the guard that stopped this from
// shipping silently the first time: a detector can add an issue type without
// remediation copy and nothing else in the build complains.
func TestFindingFixes_CoversEveryIssueType(t *testing.T) {
	t.Parallel()
	issues := detectIssueTypes(t)

	var missing []string
	for issue, path := range issues {
		if strings.TrimSpace(service.FindingFixesExported[issue]) == "" {
			missing = append(missing, issue+" ("+path+")")
		}
	}
	if len(missing) > 0 {
		t.Errorf(
			"issue types with no remediation hint — add them to findingFixes in internal/service/findings.go:\n\t%s",
			strings.Join(missing, "\n\t"),
		)
	}
}

// TestFindingFixes_NoOrphans catches the reverse drift: a hint whose issue type
// no longer exists is dead copy that reads as coverage.
func TestFindingFixes_NoOrphans(t *testing.T) {
	t.Parallel()
	issues := detectIssueTypes(t)

	var orphans []string
	for issue := range service.FindingFixesExported {
		if _, ok := issues[issue]; !ok {
			orphans = append(orphans, issue)
		}
	}
	if len(orphans) > 0 {
		t.Errorf("findingFixes entries for issue types no detector emits: %v", orphans)
	}
}

// TestFindingsService_ListByDomain_PopulatesFixHint exercises the full read path
// so the hint is proven to survive the store row -> FindingView mapping, not just
// the map lookup.
func TestFindingsService_ListByDomain_PopulatesFixHint(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	tenantID := createTenant(t, ctx, pc, "owner@example.com")
	p := ownerPrincipal(tenantID)

	d := seedDomain(t, ctx, pc, tenantID, "fix.example.com")
	seedFinding(
		t, ctx, pc, tenantID, "fix.example.com",
		"email_security", "missing_spf", "high", "No SPF record",
	)

	res, err := svc.FindingsService().ListByDomain(ctx, p, d.Uid)
	if err != nil {
		t.Fatalf("list by domain: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	if got := res.Findings[0].FixHint; got == "" {
		t.Error("FixHint is empty; the remediation catalogue is not wired into the read path")
	} else if !strings.Contains(got, "SPF") {
		t.Errorf("FixHint = %q, want the missing_spf remediation", got)
	}
}
