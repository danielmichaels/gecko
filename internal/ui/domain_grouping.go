package ui

import (
	"sort"
	"strconv"

	"github.com/danielmichaels/gecko/internal/ui/templates"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var severityOrder = []string{"crit", "warn", "scan", "ok"}

func severityRank(s string) int {
	for i, v := range severityOrder {
		if v == s {
			return i
		}
	}
	return len(severityOrder) - 1
}

// rowSeverity is a row's effective severity for rollup: scanning rows report
// "scan"; otherwise findings severity drives it. Distinct from the status-only
// DomainRowView.Severity so flat-mode rendering is unaffected.
func rowSeverity(r templates.DomainRowView) string {
	if r.Severity == "scan" {
		return "scan"
	}
	switch r.FindingsSeverity {
	case "crit", "warn":
		return r.FindingsSeverity
	default:
		return "ok"
	}
}

func apexOf(name string) string {
	apex, err := publicsuffix.Domain(name)
	if err != nil || apex == "" {
		return name
	}
	return apex
}

func groupDomainsByApex(rows []templates.DomainRowView) []templates.DomainGroupView {
	index := make(map[string]int)
	groups := make([]templates.DomainGroupView, 0)

	for _, r := range rows {
		apex := apexOf(r.Name)
		i, ok := index[apex]
		if !ok {
			i = len(groups)
			index[apex] = i
			groups = append(groups, templates.DomainGroupView{
				Apex:   apex,
				Header: templates.DomainRowView{Name: apex, RecordCount: "—", LastScan: "—"},
			})
		}
		g := &groups[i]
		if r.Name == apex {
			g.Header = r
			g.HasOwn = true
		} else {
			g.Children = append(g.Children, r)
		}
	}

	for i := range groups {
		g := &groups[i]
		g.SubCount = len(g.Children)
		sort.Slice(
			g.Children,
			func(a, b int) bool { return g.Children[a].Name < g.Children[b].Name },
		)

		members := make([]templates.DomainRowView, 0, len(g.Children)+1)
		if g.HasOwn {
			members = append(members, g.Header)
		}
		members = append(members, g.Children...)

		g.RollupSeverity, g.Rollup = rollup(members)
		g.FindingsSeverity, g.FindingsLabel = apexBadge(g.RollupSeverity, members)
	}
	return groups
}

func rollup(members []templates.DomainRowView) (worst string, distinct []string) {
	seen := make(map[string]bool)
	worstRank := len(severityOrder) - 1
	for _, m := range members {
		s := rowSeverity(m)
		seen[s] = true
		if r := severityRank(s); r < worstRank {
			worstRank = r
		}
	}
	worst = severityOrder[worstRank]
	for _, s := range severityOrder {
		if seen[s] {
			distinct = append(distinct, s)
		}
	}
	return worst, distinct
}

func apexBadge(worst string, members []templates.DomainRowView) (class, label string) {
	count := 0
	for _, m := range members {
		if rowSeverity(m) == worst {
			count++
		}
	}
	switch worst {
	case "crit":
		return "crit", plural(count, "critical", "critical")
	case "warn":
		return "warn", plural(count, "warning", "warnings")
	case "scan":
		return "info", "scanning"
	default:
		return "ok", "clean"
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// distinctApexes returns the sorted registrable apexes present in rows, for the
// top-level filter dropdown.
func distinctApexes(rows []templates.DomainRowView) []string {
	seen := make(map[string]bool)
	var out []string
	for _, r := range rows {
		a := apexOf(r.Name)
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}
