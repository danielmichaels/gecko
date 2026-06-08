package templates_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/ui/templates"
)

func TestLoginPageRender(t *testing.T) {
	var buf bytes.Buffer
	err := templates.LoginPage(templates.LoginPageProps{
		CSRFToken: "test-csrf-token",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("LoginPage render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Sign in") {
		t.Error("expected 'Sign in' in LoginPage output")
	}
	// Guards the datastar event-binding syntax: the keyed `on` plugin needs a
	// colon (data-on:click), not a hyphen — the hyphen form silently binds
	// nothing and the form does nothing on click.
	if !strings.Contains(out, `data-on:click="@post('/app/login')"`) {
		t.Error(
			"expected colon-form datastar submit binding data-on:click=\"@post('/app/login')\" in LoginPage output",
		)
	}
	if !strings.Contains(out, "/static/app.css") {
		t.Error("expected '/static/app.css' link in LoginPage output")
	}
}

func TestLoginPageErrorRender(t *testing.T) {
	var buf bytes.Buffer
	err := templates.LoginPage(templates.LoginPageProps{
		CSRFToken: "tok",
		Error:     "invalid credentials",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("LoginPage error render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "invalid credentials") {
		t.Error("expected error message in LoginPage output")
	}
}

func TestAcceptInvitePageRender(t *testing.T) {
	var buf bytes.Buffer
	err := templates.AcceptInvitePage(templates.AcceptInvitePageProps{
		CSRFToken:    "tok",
		Token:        "inv_abc123",
		TenantName:   "acme-corp",
		InviterEmail: "admin@acme.io",
		Role:         "member",
		InviteeEmail: "new@acme.io",
		Expiry:       "in 46h",
	}).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("AcceptInvitePage render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "acme-corp") {
		t.Error("expected tenant name in AcceptInvitePage output")
	}
	if !strings.Contains(out, "new@acme.io") {
		t.Error("expected invitee email in AcceptInvitePage output")
	}
	if !strings.Contains(out, "inv_abc123") {
		t.Error("expected token in AcceptInvitePage output")
	}
}

func TestDomainsPageRender(t *testing.T) {
	var buf bytes.Buffer
	props := templates.DomainsPageProps{
		Shell: templates.AppShellProps{
			TenantName:   "acme-corp",
			UserEmail:    "daniel",
			UserInitials: "DM",
			ActiveNav:    "domains",
			AppVersion:   "v0.3.1-alpha",
			ResolverOK:   true,
			CSRFToken:    "tok",
		},
		Stats: templates.DomainsStats{
			Tracked:  "3",
			Critical: "2",
			Warnings: "1",
			Records:  "52",
		},
		Layout: "flat",
		Domains: []templates.DomainRowView{
			{
				UID:              "dom_001",
				Name:             "example.com",
				Severity:         "crit",
				RecordCount:      "14",
				FindingsLabel:    "2 critical",
				FindingsSeverity: "crit",
				LastScan:         "2h ago",
			},
		},
	}
	err := templates.DomainsPage(props).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("DomainsPage render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com") {
		t.Error("expected domain name in DomainsPage output")
	}
	if !strings.Contains(out, "Domains") {
		t.Error("expected 'Domains' heading in DomainsPage output")
	}
	if !strings.Contains(out, "domains-rows") {
		t.Error("expected 'domains-rows' container in DomainsPage output")
	}
	// Search promoted to primary: debounced datastar GET (colon-form binding).
	if !strings.Contains(out, `data-on:input__debounce.300ms="$offset = 0; @get('/app/domains')"`) {
		t.Error("expected debounced search binding (resetting offset) in DomainsPage output")
	}
	// Add-domain demoted to a drawer toggled by the drawerOpen signal.
	if !strings.Contains(out, `class="drawer"`) {
		t.Error("expected add-domain drawer in DomainsPage output")
	}
	if !strings.Contains(out, "$drawerOpen = true") {
		t.Error("expected drawer-open trigger in DomainsPage output")
	}
}

func TestDomainTableBodyNestedRender(t *testing.T) {
	props := templates.DomainsPageProps{
		Layout: "nested",
		Groups: []templates.DomainGroupView{
			{
				Apex:   "example.com",
				HasOwn: true,
				Header: templates.DomainRowView{
					UID:         "dom_1",
					Name:        "example.com",
					RecordCount: "14",
					LastScan:    "2m ago",
				},
				Children: []templates.DomainRowView{
					{
						UID:              "dom_2",
						Name:             "api.example.com",
						RecordCount:      "6",
						LastScan:         "2m ago",
						FindingsSeverity: "warn",
						FindingsLabel:    "SPF soft-fail",
					},
				},
				SubCount:         1,
				RollupSeverity:   "crit",
				Rollup:           []string{"crit", "warn"},
				FindingsSeverity: "crit",
				FindingsLabel:    "1 critical",
			},
		},
	}
	var buf bytes.Buffer
	if err := templates.DomainTableBody(props, "tok").Render(context.Background(), &buf); err != nil {
		t.Fatalf("DomainTableBody render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "apex") {
		t.Error("expected apex row class in nested body output")
	}
	if !strings.Contains(out, "<b>example.com</b>") {
		t.Error("expected bold apex name in nested body output")
	}
	// Tracked apex (HasOwn) name links to its detail page so its own findings
	// are reachable from nested mode.
	if !strings.Contains(out, `href="/app/domains/dom_1"`) {
		t.Error("expected tracked apex name to link to its detail page")
	}
	if !strings.Contains(out, "<b>api</b>.example.com") {
		t.Error("expected child FQDN (label + apex) in nested body output")
	}
	if !strings.Contains(out, "1 sub") {
		t.Error("expected '1 sub' pill in nested body output")
	}
	// Collapse toggle: colon-form binding mutating the $collapsed array signal.
	if !strings.Contains(out, "data-on:click") {
		t.Error("expected colon-form data-on:click on apex row")
	}
	if !strings.Contains(out, "$collapsed") {
		t.Error("expected $collapsed array signal expression on apex row")
	}
}

func TestDomainsPageLayoutToggleRender(t *testing.T) {
	props := templates.DomainsPageProps{
		Shell: templates.AppShellProps{
			ActiveNav: "domains",
			CSRFToken: "tok",
		},
		Stats:      templates.DomainsStats{Tracked: "1"},
		Layout:     "nested",
		TLDOptions: []string{"example.com", "acme.io"},
	}
	var buf bytes.Buffer
	if err := templates.DomainsPage(props).Render(context.Background(), &buf); err != nil {
		t.Fatalf("DomainsPage render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `data-bind="tld"`) {
		t.Error("expected tld-bound select in toolbar")
	}
	if !strings.Contains(out, "All top-level") {
		t.Error("expected 'All top-level' default option in tld filter")
	}
	if !strings.Contains(out, "example.com") {
		t.Error("expected a tld option for example.com")
	}
	// Layout toggle: colon-form binding setting the $layout signal to 'flat'.
	if !strings.Contains(out, "$layout = 'flat'") {
		t.Error("expected flat layout toggle binding")
	}
}

func TestDomainRowsFragmentRender(t *testing.T) {
	var buf bytes.Buffer
	rows := []templates.DomainRowView{
		{
			UID:              "dom_1",
			Name:             "a.example.com",
			Severity:         "ok",
			RecordCount:      "—",
			FindingsLabel:    "healthy",
			FindingsSeverity: "ok",
			LastScan:         "1h ago",
		},
	}
	if err := templates.DomainRowsFragment(rows, "tok").Render(context.Background(), &buf); err != nil {
		t.Fatalf("DomainRowsFragment render error: %v", err)
	}
	if !strings.Contains(buf.String(), "a.example.com") {
		t.Error("expected domain name in populated fragment")
	}

	var empty bytes.Buffer
	if err := templates.DomainRowsFragment(nil, "tok").Render(context.Background(), &empty); err != nil {
		t.Fatalf("DomainRowsFragment empty render error: %v", err)
	}
	if !strings.Contains(empty.String(), "trow-empty") {
		t.Error("expected empty-state row in empty DomainRowsFragment output")
	}
}

func TestDomainRowRender(t *testing.T) {
	var buf bytes.Buffer
	row := templates.DomainRowView{
		UID:              "dom_002",
		Name:             "test.example.com",
		Severity:         "warn",
		RecordCount:      "9",
		FindingsLabel:    "dangling CNAME?",
		FindingsSeverity: "warn",
		LastScan:         "3d ago",
	}
	err := templates.DomainRow(row, "csrf-tok").Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("DomainRow render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "test.example.com") {
		t.Error("expected domain name in DomainRow output")
	}
	if !strings.Contains(out, "domain-row-dom_002") {
		t.Error("expected row id in DomainRow output")
	}
}

func TestDomainDetailPageRender(t *testing.T) {
	var buf bytes.Buffer
	props := templates.DomainDetailPageProps{
		Shell: templates.AppShellProps{
			TenantName:   "acme-corp",
			UserEmail:    "daniel",
			UserInitials: "DM",
			ActiveNav:    "domains",
			AppVersion:   "v0.3.1-alpha",
			ResolverOK:   true,
			CSRFToken:    "tok",
		},
		UID:              "dom_001",
		Name:             "example.com",
		Severity:         "crit",
		RecordCount:      "14",
		FindingsCount:    "2",
		FindingsSeverity: "crit",
		Type:             "tld",
		Source:           "user-supplied",
		Added:            "2026-05-12",
		Scanned:          "2h ago",
	}
	err := templates.DomainDetailPage(props).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("DomainDetailPage render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com") {
		t.Error("expected domain name in DomainDetailPage output")
	}
	if !strings.Contains(out, "records-content") {
		t.Error("expected records-content lazy panel in DomainDetailPage output")
	}
	if !strings.Contains(out, "timeline-content") {
		t.Error("expected timeline-content lazy panel in DomainDetailPage output")
	}
	if !strings.Contains(out, "timeline-full-content") {
		t.Error("expected timeline-full-content panel in DomainDetailPage output")
	}
	if !strings.Contains(out, "findings-content") {
		t.Error("expected findings-content panel in DomainDetailPage output")
	}
	// Tabs are signal-driven (colon-form on:click), not dead hash anchors.
	if !strings.Contains(out, "$tab = 'records'") {
		t.Error("expected signal-driven Records tab in DomainDetailPage output")
	}
	if !strings.Contains(out, "/timeline/full") {
		t.Error("expected lazy timeline-full fetch in DomainDetailPage output")
	}
	if !strings.Contains(out, "domains") {
		t.Error("expected back link in DomainDetailPage output")
	}
}

func TestTimelineFullRender(t *testing.T) {
	var buf bytes.Buffer
	v := templates.TimelineFullView{
		ScanCount:   1,
		ChangeCount: 2,
		Groups: []templates.ScanGroupView{
			{
				ScanID:      "scan_abc123",
				When:        "2026-06-07 21:52",
				Meta:        "user_supplied",
				ChangeCount: 2,
				Changes: []templates.ChangeView{
					{Kind: "add", Op: "+", Entity: "a_record", Value: "66.241.125.84"},
					{Kind: "del", Op: "−", Entity: "txt_record", Value: "old-value"},
				},
			},
		},
	}
	if err := templates.TimelineFull(v).Render(context.Background(), &buf); err != nil {
		t.Fatalf("TimelineFull render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "scan_abc123") {
		t.Error("expected scan id in TimelineFull output")
	}
	if !strings.Contains(out, "chg add") {
		t.Error("expected add-change class in TimelineFull output")
	}
	if !strings.Contains(out, "a_record") {
		t.Error("expected entity in TimelineFull output")
	}
}

func TestFindingsPanelRender(t *testing.T) {
	var buf bytes.Buffer
	v := templates.FindingsView{
		TotalCount:    2,
		CriticalCount: 1,
		WarningCount:  1,
		Findings: []templates.FindingCardView{
			{
				SevClass:    "crit",
				Severity:    "critical",
				Icon:        "!",
				Title:       "No DMARC policy published",
				Description: "No _dmarc record was found.",
				Evidence:    "dig _dmarc.example.com TXT → NXDOMAIN",
				FixHint:     "publish v=DMARC1; p=none",
			},
			{
				SevClass:    "warn",
				Severity:    "medium",
				Icon:        "▲",
				Title:       "SPF uses soft-fail (~all)",
				Description: "Soft fail.",
				Evidence:    "v=spf1 ~all",
			},
		},
	}
	if err := templates.FindingsPanel(v).Render(context.Background(), &buf); err != nil {
		t.Fatalf("FindingsPanel render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No DMARC policy published") {
		t.Error("expected finding title in FindingsPanel output")
	}
	if !strings.Contains(out, "finding f-crit") {
		t.Error("expected severity class in FindingsPanel output")
	}
	if !strings.Contains(out, "Fix:") {
		t.Error("expected fix line in FindingsPanel output")
	}
}

func TestFindingsPanelEmptyRender(t *testing.T) {
	var buf bytes.Buffer
	if err := templates.FindingsPanel(templates.FindingsView{}).Render(context.Background(), &buf); err != nil {
		t.Fatalf("FindingsPanel empty render error: %v", err)
	}
	if !strings.Contains(buf.String(), "no findings") {
		t.Error("expected empty-state message in FindingsPanel output")
	}
}

func TestRecordsTableRender(t *testing.T) {
	var buf bytes.Buffer
	v := templates.RecordsView{
		Title: "DNS records",
		Count: "3 · A MX TXT",
		Rows: []templates.RecordRowView{
			{Type: "A", Value: "93.184.216.34", TTL: "3600", Flagged: false},
			{Type: "TXT", Value: "v=spf1 +all", TTL: "300", Flagged: true},
		},
	}
	err := templates.RecordsTable(v).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("RecordsTable render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "93.184.216.34") {
		t.Error("expected record value in RecordsTable output")
	}
	if !strings.Contains(out, "flag") {
		t.Error("expected flagged record class in RecordsTable output")
	}
}

func TestTimelineRender(t *testing.T) {
	var buf bytes.Buffer
	v := templates.TimelineView{
		Groups: []templates.TimelineItemView{
			{
				Kind: "scan",
				When: "2026-06-06 20:24 · SCAN #41",
				What: "Scan completed · 14 records observed",
			},
			{Kind: "del", When: "2026-06-06 20:24", What: "removed A 93.184.216.10"},
			{Kind: "add", When: "2026-05-12 11:08 · SCAN #1", What: "Domain added · first sweep"},
		},
	}
	err := templates.Timeline(v).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Timeline render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SCAN #41") {
		t.Error("expected scan entry in Timeline output")
	}
	if !strings.Contains(out, "tl-item") {
		t.Error("expected tl-item class in Timeline output")
	}
}

func TestComingSoonRender(t *testing.T) {
	var buf bytes.Buffer
	props := templates.ComingSoonProps{
		Shell: templates.AppShellProps{
			TenantName:   "acme-corp",
			UserEmail:    "daniel",
			UserInitials: "DM",
			ActiveNav:    "findings",
			AppVersion:   "v0.3.1-alpha",
			ResolverOK:   true,
			CSRFToken:    "tok",
		},
		Glyph: "⚠",
		Title: "Findings",
		Blurb: "Aggregated security findings across every domain.",
	}
	err := templates.ComingSoon(props).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("ComingSoon render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "On the roadmap") {
		t.Error("expected 'On the roadmap' badge in ComingSoon output")
	}
	if !strings.Contains(out, "Findings") {
		t.Error("expected title in ComingSoon output")
	}
}

func TestContentErrorRender(t *testing.T) {
	var buf bytes.Buffer
	props := templates.ContentErrorProps{
		Message:  "failed to load records",
		RetryURL: "/app/domains/dom_001/records",
	}
	err := templates.ContentError(props).Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("ContentError render error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "failed to load records") {
		t.Error("expected error message in ContentError output")
	}
	if !strings.Contains(out, "Retry") {
		t.Error("expected 'Retry' button in ContentError output")
	}
}
