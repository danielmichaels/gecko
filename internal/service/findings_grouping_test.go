package service

import (
	"testing"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// tenantRow builds a synthetic UNION row for the pure grouping tests. Status is
// always open; details/value carry placeholder evidence.
func tenantRow(
	domainUID, domainName, kind string,
	sev store.FindingSeverity,
	issueType string,
) store.FindingsListByTenantRow {
	return store.FindingsListByTenantRow{
		FindingUid: kind + "_" + domainUID + "_" + issueType,
		DomainUid:  domainUID,
		DomainName: domainName,
		Kind:       kind,
		Severity:   sev,
		Status:     store.FindingStatusOpen,
		IssueType:  issueType,
		Value:      pgtype.Text{String: "evidence", Valid: true},
		Details:    pgtype.Text{String: "detail text", Valid: true},
	}
}

func domainNames(groups []DomainFindingGroup) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g.DomainName
	}
	return out
}

func TestBuildTenantFindings_GroupingAndOrdering(t *testing.T) {
	// Rows arrive pre-sorted domain-then-severity (as the SQL guarantees).
	rows := []store.FindingsListByTenantRow{
		tenantRow("a", "a.com", "DMARC", store.FindingSeverityHigh, "weak_dmarc_policy"),
		tenantRow("b", "b.com", "SPF", store.FindingSeverityCritical, "missing_spf"),
		tenantRow("b", "b.com", "DMARC", store.FindingSeverityCritical, "missing_dmarc"),
		tenantRow("c", "c.com", "ZONE", store.FindingSeverityCritical, "zone_transfer_exposed"),
	}

	got := buildTenantFindings(rows, FindingsListOptions{})

	// Worst-first: b and c are both critical, tie broken by count desc (b has 2),
	// then a (high) last.
	want := []string{"b.com", "c.com", "a.com"}
	names := domainNames(got.Groups)
	if len(names) != len(want) {
		t.Fatalf("group count = %d, want %d (%v)", len(names), len(want), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("group[%d] = %q, want %q (order: %v)", i, names[i], want[i], names)
		}
	}

	if got.Totals.Open != 4 {
		t.Errorf("Totals.Open = %d, want 4", got.Totals.Open)
	}
	if got.Totals.Critical != 3 || got.Totals.High != 1 {
		t.Errorf("Totals crit/high = %d/%d, want 3/1", got.Totals.Critical, got.Totals.High)
	}
	if got.Totals.DomainCount != 3 {
		t.Errorf("Totals.DomainCount = %d, want 3", got.Totals.DomainCount)
	}
}

func TestBuildTenantFindings_WithinGroupSeverityOrderPreserved(t *testing.T) {
	rows := []store.FindingsListByTenantRow{
		tenantRow("a", "a.com", "SPF", store.FindingSeverityCritical, "missing_spf"),
		tenantRow("a", "a.com", "DMARC", store.FindingSeverityHigh, "weak_dmarc_policy"),
		tenantRow("a", "a.com", "DKIM", store.FindingSeverityLow, "test_mode_enabled"),
	}

	got := buildTenantFindings(rows, FindingsListOptions{})
	if len(got.Groups) != 1 {
		t.Fatalf("group count = %d, want 1", len(got.Groups))
	}
	wantTiers := []string{"crit", "high", "low"}
	for i, f := range got.Groups[0].Findings {
		if f.Tier != wantTiers[i] {
			t.Errorf("finding[%d].Tier = %q, want %q", i, f.Tier, wantTiers[i])
		}
	}
}

func TestBuildTenantFindings_Filters(t *testing.T) {
	rows := []store.FindingsListByTenantRow{
		tenantRow("a", "acme.com", "SPF", store.FindingSeverityCritical, "missing_spf"),
		tenantRow("a", "acme.com", "DMARC", store.FindingSeverityHigh, "weak_dmarc_policy"),
		tenantRow(
			"b",
			"blog.example.org",
			"DKIM",
			store.FindingSeverityMedium,
			"test_mode_enabled",
		),
		tenantRow("c", "shop.example.org", "SPF", store.FindingSeverityLow, "soft_fail_spf_policy"),
	}

	t.Run("severity narrows to one tier", func(t *testing.T) {
		got := buildTenantFindings(rows, FindingsListOptions{Severity: "crit"})
		if got.Totals.Open != 1 || got.Totals.Critical != 1 {
			t.Errorf("open/crit = %d/%d, want 1/1", got.Totals.Open, got.Totals.Critical)
		}
		if got.Totals.High != 0 {
			t.Errorf("High = %d, want 0 (filtered out)", got.Totals.High)
		}
		if len(got.Groups) != 1 || got.Groups[0].DomainName != "acme.com" {
			t.Errorf("groups = %v, want [acme.com]", domainNames(got.Groups))
		}
		// SeverityCounts is faceted: ignores the active severity filter, so all
		// tiers keep their counts for the chips.
		if got.SeverityCounts["high"] != 1 || got.SeverityCounts["med"] != 1 {
			t.Errorf("SeverityCounts not faceted: %v", got.SeverityCounts)
		}
	})

	t.Run("kind narrows and KindCounts stays faceted", func(t *testing.T) {
		got := buildTenantFindings(rows, FindingsListOptions{Kind: "SPF"})
		if got.Totals.Open != 2 {
			t.Errorf("open = %d, want 2 (two SPF)", got.Totals.Open)
		}
		// KindCounts ignores the kind filter so the dropdown stays populated.
		if got.KindCounts["DKIM"] != 1 || got.KindCounts["DMARC"] != 1 {
			t.Errorf("KindCounts not faceted: %v", got.KindCounts)
		}
		if got.KindCounts["SPF"] != 2 {
			t.Errorf("KindCounts[SPF] = %d, want 2", got.KindCounts["SPF"])
		}
	})

	t.Run("domain substring is case-insensitive", func(t *testing.T) {
		got := buildTenantFindings(rows, FindingsListOptions{DomainQuery: "EXAMPLE.ORG"})
		if got.Totals.DomainCount != 2 {
			t.Errorf("domains = %v, want 2", domainNames(got.Groups))
		}
		if got.KindCounts["SPF"] != 1 {
			t.Errorf("KindCounts[SPF] = %d, want 1 (only shop.example.org)", got.KindCounts["SPF"])
		}
	})
}

func TestBuildTenantFindings_Empty(t *testing.T) {
	got := buildTenantFindings(nil, FindingsListOptions{})
	if len(got.Groups) != 0 {
		t.Errorf("groups = %d, want 0", len(got.Groups))
	}
	if got.Totals != (FindingTotals{}) {
		t.Errorf("totals = %+v, want zero value", got.Totals)
	}
}

func TestBuildTenantFindings_RefusedZoneIsHealthy(t *testing.T) {
	rows := []store.FindingsListByTenantRow{
		tenantRow("a", "a.com", "ZONE", store.FindingSeverityHigh, "zone_transfer_refused"),
	}
	got := buildTenantFindings(rows, FindingsListOptions{})
	if len(got.Groups) != 1 || len(got.Groups[0].Findings) != 1 {
		t.Fatalf("unexpected groups: %+v", got.Groups)
	}
	f := got.Groups[0].Findings[0]
	if f.Tier != "ok" || f.SevClass != "ok" {
		t.Errorf("refused zone tier/class = %q/%q, want ok/ok", f.Tier, f.SevClass)
	}
	if got.Totals.High != 0 {
		t.Errorf("Totals.High = %d, want 0 (refused is healthy)", got.Totals.High)
	}
}
