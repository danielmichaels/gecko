package ui

import (
	"reflect"
	"testing"

	"github.com/danielmichaels/gecko/internal/ui/templates"
)

// row is a tiny constructor for the fields grouping actually reads.
func row(uid, name, severity, findingsSeverity string) templates.DomainRowView {
	return templates.DomainRowView{
		UID:              uid,
		Name:             name,
		Severity:         severity,
		FindingsSeverity: findingsSeverity,
	}
}

func TestGroupDomainsByApex_NestsChildrenUnderApex(t *testing.T) {
	rows := []templates.DomainRowView{
		row("dom_1", "example.com", "ok", "ok"),
		row("dom_2", "api.example.com", "ok", "ok"),
		row("dom_3", "www.example.com", "ok", "ok"),
	}

	groups := groupDomainsByApex(rows)

	if len(groups) != 1 {
		t.Fatalf("want 1 group, got %d", len(groups))
	}
	g := groups[0]
	if g.Apex != "example.com" {
		t.Errorf("apex: want example.com, got %q", g.Apex)
	}
	if !g.HasOwn {
		t.Error("HasOwn: want true (apex itself tracked)")
	}
	if g.Header.UID != "dom_1" {
		t.Errorf("header UID: want dom_1, got %q", g.Header.UID)
	}
	if g.SubCount != 2 {
		t.Errorf("SubCount: want 2, got %d", g.SubCount)
	}
}

func TestGroupDomainsByApex_ChildrenSortedByName(t *testing.T) {
	rows := []templates.DomainRowView{
		row("dom_1", "example.com", "ok", "ok"),
		row("dom_2", "www.example.com", "ok", "ok"),
		row("dom_3", "api.example.com", "ok", "ok"),
	}

	g := groupDomainsByApex(rows)[0]

	got := []string{g.Children[0].Name, g.Children[1].Name}
	want := []string{"api.example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("children order: want %v, got %v", want, got)
	}
}

func TestGroupDomainsByApex_GroupOrderIsFirstAppearance(t *testing.T) {
	rows := []templates.DomainRowView{
		row("dom_1", "zeta.com", "ok", "ok"),
		row("dom_2", "alpha.com", "ok", "ok"),
		row("dom_3", "www.zeta.com", "ok", "ok"),
	}

	groups := groupDomainsByApex(rows)

	if groups[0].Apex != "zeta.com" || groups[1].Apex != "alpha.com" {
		t.Errorf(
			"group order: want [zeta.com alpha.com], got [%s %s]",
			groups[0].Apex,
			groups[1].Apex,
		)
	}
}

func TestGroupDomainsByApex_RollupUsesWorstChildFindings(t *testing.T) {
	rows := []templates.DomainRowView{
		row("dom_1", "example.com", "ok", "ok"),
		row("dom_2", "www.example.com", "ok", "warn"),
		row("dom_3", "staging.example.com", "ok", "crit"),
	}

	g := groupDomainsByApex(rows)[0]

	// The accent reflects the worst severity across the apex and its children.
	if g.RollupSeverity != "crit" {
		t.Errorf("RollupSeverity: want crit, got %q", g.RollupSeverity)
	}
	// Distinct severities, worst-first: crit, warn, ok.
	want := []string{"crit", "warn", "ok"}
	if !reflect.DeepEqual(g.Rollup, want) {
		t.Errorf("Rollup: want %v, got %v", want, g.Rollup)
	}
}

func TestGroupDomainsByApex_TrackedApexBadgeShowsOwnFindings(t *testing.T) {
	// Apex itself is critical; every child is clean. The badge must reflect the
	// apex's OWN status, not a child-count rollup.
	apex := templates.DomainRowView{
		UID:              "dom_1",
		Name:             "example.com",
		FindingsSeverity: "crit",
		FindingsLabel:    "critical",
	}
	rows := []templates.DomainRowView{
		apex,
		row("dom_2", "www.example.com", "ok", "ok"),
		row("dom_3", "api.example.com", "ok", "ok"),
	}

	g := groupDomainsByApex(rows)[0]

	if g.FindingsSeverity != "crit" || g.FindingsLabel != "critical" {
		t.Errorf(
			"apex badge: want crit/critical (own), got %s/%s",
			g.FindingsSeverity,
			g.FindingsLabel,
		)
	}
	if g.RollupSeverity != "crit" {
		t.Errorf("RollupSeverity: want crit, got %q", g.RollupSeverity)
	}
	// Spread present in the dots: crit (apex) + ok (children).
	if !reflect.DeepEqual(g.Rollup, []string{"crit", "ok"}) {
		t.Errorf("Rollup dots: want [crit ok], got %v", g.Rollup)
	}
}

func TestGroupDomainsByApex_ScanningChildDrivesScanRollup(t *testing.T) {
	rows := []templates.DomainRowView{
		row("dom_1", "legacy-shop.co", "ok", "ok"),
		row("dom_2", "shop.legacy-shop.co", "scan", ""),
	}

	g := groupDomainsByApex(rows)[0]

	// A scanning child drives the group accent to "scan" even though the tracked
	// apex's own status is clean.
	if g.RollupSeverity != "scan" {
		t.Errorf("RollupSeverity: want scan, got %q", g.RollupSeverity)
	}
	if !reflect.DeepEqual(g.Rollup, []string{"scan", "ok"}) {
		t.Errorf("Rollup dots: want [scan ok], got %v", g.Rollup)
	}
}

func TestGroupDomainsByApex_SyntheticHeaderWhenApexUntracked(t *testing.T) {
	rows := []templates.DomainRowView{
		row("dom_1", "api.untracked.com", "ok", "warn"),
	}

	g := groupDomainsByApex(rows)[0]

	if g.HasOwn {
		t.Error("HasOwn: want false (apex itself not tracked)")
	}
	if g.Header.UID != "" {
		t.Errorf("synthetic header UID: want empty, got %q", g.Header.UID)
	}
	if g.Header.Name != "untracked.com" {
		t.Errorf("synthetic header name: want untracked.com, got %q", g.Header.Name)
	}
	if g.Header.RecordCount != "—" || g.Header.LastScan != "—" {
		t.Errorf(
			"synthetic header placeholders: want —/—, got %s/%s",
			g.Header.RecordCount,
			g.Header.LastScan,
		)
	}
	// Rollup excludes the synthetic header (it has no own findings).
	if g.RollupSeverity != "warn" {
		t.Errorf("RollupSeverity: want warn, got %q", g.RollupSeverity)
	}
	// With no own status, the synthetic apex badge summarises the children.
	if g.FindingsSeverity != "warn" || g.FindingsLabel != "1 warning" {
		t.Errorf(
			"synthetic apex badge: want warn/'1 warning', got %s/%s",
			g.FindingsSeverity,
			g.FindingsLabel,
		)
	}
}

func TestGroupDomainsByApex_MultiLabelPSL(t *testing.T) {
	rows := []templates.DomainRowView{
		row("dom_1", "example.co.uk", "ok", "ok"),
		row("dom_2", "www.example.co.uk", "ok", "ok"),
	}

	groups := groupDomainsByApex(rows)

	if len(groups) != 1 {
		t.Fatalf("want 1 group for co.uk apex, got %d", len(groups))
	}
	if groups[0].Apex != "example.co.uk" {
		t.Errorf("apex: want example.co.uk, got %q", groups[0].Apex)
	}
	if groups[0].SubCount != 1 {
		t.Errorf("SubCount: want 1, got %d", groups[0].SubCount)
	}
}

func TestGroupDomainsByApex_CleanTrackedApexShowsOwnBadge(t *testing.T) {
	rows := []templates.DomainRowView{
		{UID: "dom_1", Name: "corp.net", FindingsSeverity: "ok", FindingsLabel: "healthy"},
	}

	g := groupDomainsByApex(rows)[0]

	if g.RollupSeverity != "ok" {
		t.Errorf("RollupSeverity: want ok, got %q", g.RollupSeverity)
	}
	// Tracked apex with no children shows its own healthy badge.
	if g.FindingsSeverity != "ok" || g.FindingsLabel != "healthy" {
		t.Errorf(
			"apex badge: want ok/healthy (own), got %s/%s",
			g.FindingsSeverity,
			g.FindingsLabel,
		)
	}
}

func TestGroupDomainsByApex_SyntheticCleanGroupBadge(t *testing.T) {
	// Untracked apex with only clean children: rollup badge reads "clean".
	rows := []templates.DomainRowView{
		row("dom_1", "www.corp.net", "ok", "ok"),
	}

	g := groupDomainsByApex(rows)[0]

	if g.HasOwn {
		t.Fatal("HasOwn: want false (apex untracked)")
	}
	if g.FindingsSeverity != "ok" || g.FindingsLabel != "clean" {
		t.Errorf(
			"synthetic apex badge: want ok/clean, got %s/%s",
			g.FindingsSeverity,
			g.FindingsLabel,
		)
	}
}

func TestDistinctApexes_SortedAndDeduped(t *testing.T) {
	rows := []templates.DomainRowView{
		row("dom_1", "www.zeta.com", "ok", "ok"),
		row("dom_2", "zeta.com", "ok", "ok"),
		row("dom_3", "alpha.com", "ok", "ok"),
		row("dom_4", "api.alpha.com", "ok", "ok"),
	}

	got := distinctApexes(rows)
	want := []string{"alpha.com", "zeta.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("distinctApexes: want %v, got %v", want, got)
	}
}
