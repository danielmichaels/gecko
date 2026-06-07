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
	if !strings.Contains(out, "fleet status") {
		t.Error("expected 'fleet status' in LoginPage output")
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
		UID:           "dom_001",
		Name:          "example.com",
		Severity:      "crit",
		RecordCount:   "14",
		FindingsCount: "2",
		Type:          "tld",
		Source:        "user-supplied",
		Added:         "2026-05-12",
		Scanned:       "2h ago",
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
	if !strings.Contains(out, "domains") {
		t.Error("expected back link in DomainDetailPage output")
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
