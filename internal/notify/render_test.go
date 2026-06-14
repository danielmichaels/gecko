package notify

import (
	"strings"
	"testing"
	"time"
)

func TestRenderDailyDigest_SummaryAndHighImpact(t *testing.T) {
	summary := DigestSummary{
		Created:    3,
		Updated:    1,
		Deleted:    0,
		HighImpact: 1,
		Breakdown: []BreakdownItem{
			{EntityType: "a_record", ChangeType: "created", Count: 3},
			{EntityType: "dmarc_finding", ChangeType: "updated", Count: 1},
		},
	}
	high := []HighImpactItem{
		{
			DomainName: "shop.example.com",
			EntityType: "dangling_cname_finding",
			ChangeType: "created",
			Severity:   "critical",
			Status:     "open",
			ObservedAt: time.Now(),
		},
	}

	n := RenderDailyDigest("Acme", "https://app.gecko.test", summary, high)

	if n.Kind != KindDailyDigest {
		t.Errorf("Kind = %q, want %q", n.Kind, KindDailyDigest)
	}
	if !strings.Contains(n.Subject, "high-impact") {
		t.Errorf("subject should flag high-impact: %q", n.Subject)
	}
	for _, want := range []string{"Acme", "shop.example.com", "critical", "https://app.gecko.test/app/domains"} {
		if !strings.Contains(n.HTML, want) {
			t.Errorf("HTML missing %q:\n%s", want, n.HTML)
		}
		if !strings.Contains(n.Text, want) {
			t.Errorf("Text missing %q:\n%s", want, n.Text)
		}
	}
	// entity types are humanized (underscores removed).
	if strings.Contains(n.HTML, "dangling_cname_finding") {
		t.Errorf("entity type not humanized in HTML:\n%s", n.HTML)
	}
}

func TestRenderDailyDigest_NoHighImpact(t *testing.T) {
	summary := DigestSummary{Created: 2, Updated: 0, Deleted: 0}
	n := RenderDailyDigest("Acme", "https://app.gecko.test", summary, nil)
	if strings.Contains(n.Subject, "high-impact") {
		t.Errorf("subject should not flag high-impact when none: %q", n.Subject)
	}
	if summary.Total() != 2 {
		t.Errorf("Total() = %d, want 2", summary.Total())
	}
}
