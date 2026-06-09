package templates_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/ui/templates"
)

func sampleScansView() templates.TenantScansView {
	return templates.TenantScansView{
		ScanCount:   3,
		DomainCount: 2,
		ChangeCount: 5,
		CleanCount:  1,
		SourceOptions: []templates.ScanSourceOption{
			{Value: "user_supplied", Class: "src-user", Label: "User", Count: 2},
			{Value: "discovered", Class: "src-disc", Label: "Discovered", Count: 1},
		},
		Days: []templates.ScanDayGroupView{
			{
				Label: "Today",
				Date:  "09 Jun",
				Scans: []templates.ScanRowView{
					{
						ScanUID: "scan_chg", DomainUID: "dom1", Label: "acme.com",
						SourceClass: "src-user", SourceLabel: "user", State: "changed",
						AbsoluteTime: "14:38", RelativeTime: "4m ago",
						ParentScanUID: "scan_prev",
						ParentURL:     "/app/domains/dom1?tab=timeline&scan=scan_prev",
						DeltaHead:     "1 change since scan_prev",
						DeltaMeta:     "scan_chg · 2026-06-09 14:38:02 UTC",
						TimelineURL:   "/app/domains/dom1?tab=timeline&scan=scan_chg",
						Segments:      []templates.ScanSegment{{Class: "u", Width: "100%"}},
						Pills:         []templates.ScanPill{{Class: "u", Glyph: "~", Count: 1}},
						Changes: []templates.ScanChangeView{
							{
								Class:      "u",
								Op:         "~",
								EntityType: "spf_finding",
								CountLabel: "1 updated",
							},
						},
					},
					{
						ScanUID: "scan_clean", DomainUID: "dom2", Label: "shop", ApexSuffix: ".example.org",
						SourceClass: "src-disc", SourceLabel: "discovered", State: "clean",
						AbsoluteTime: "11:02", RelativeTime: "3h ago",
						ParentScanUID: "scan_old",
						CleanMessage:  "Nothing changed since the previous scan — all records and findings match scan_old.",
						DeltaMeta:     "scan_clean · 2026-06-09 11:02:44 UTC",
						TimelineURL:   "/app/domains/dom2?tab=timeline&scan=scan_clean",
					},
					{
						ScanUID: "scan_base", DomainUID: "dom2", Label: "blog", ApexSuffix: ".example.org",
						SourceClass: "src-disc", SourceLabel: "discovered", State: "baseline",
						AbsoluteTime: "18:44", RelativeTime: "1d ago", IsBaseline: true,
						DeltaHead:   "baseline — 14 records first observed",
						DeltaMeta:   "scan_base · 2026-06-08 18:44:31 UTC · no parent",
						TimelineURL: "/app/domains/dom2?tab=timeline&scan=scan_base",
						Pills:       []templates.ScanPill{{Class: "c", Glyph: "+", Count: 14}},
						Changes: []templates.ScanChangeView{
							{Class: "c", Op: "+", EntityType: "a_record", CountLabel: "14 created"},
						},
					},
				},
			},
		},
	}
}

func TestScansPageRender(t *testing.T) {
	var buf bytes.Buffer
	err := templates.ScansPage(templates.ScansPageProps{
		Shell: templates.AppShellProps{ActiveNav: "scans", CSRFToken: "tok"},
		View:  sampleScansView(),
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("ScansPage render error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"◎ Scans",
		`data-on:click`,              // colon-form datastar binding (hyphen silently no-ops)
		`@get(&#39;/app/scans&#39;)`, // filter re-fetch wired
		"baseline scan",              // baseline chain text
		"no changes",                 // clean summary cell
		"first observation",          // baseline tag
		"View on timeline →",         // deep-link
		"dseg",                       // scan-scoped seg class (not the Findings .seg)
		"dpill",                      // scan-scoped pill class
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ScansPage output missing %q", want)
		}
	}
	// Must NOT recolor the Findings rollup: the changed row uses .dseg/.dpill, so
	// the bare Findings classes should not appear as the scan segment markup.
	if strings.Contains(out, `class="seg u"`) {
		t.Error("scan segment leaked the Findings .seg class instead of .dseg")
	}
}

func TestScansListFragmentEmpty(t *testing.T) {
	var buf bytes.Buffer
	err := templates.ScansListFragment(templates.TenantScansView{}).
		Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("ScansListFragment render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No scans match these filters") {
		t.Error("expected empty-state copy in ScansListFragment output")
	}
}
