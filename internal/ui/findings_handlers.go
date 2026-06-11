package ui

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/ui/templates"
	datastar "github.com/starfederation/datastar-go/datastar"
)

// handleFindingsPage renders the tenant-wide Findings roll-up. The same route
// serves the full page (browser nav) and a fragment (#findings-list) on every
// filter change, which datastar tags with the Datastar-Request header.
func (h *Handlers) handleFindingsPage(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	isDatastar := r.Header.Get("Datastar-Request") == "true"

	var opts service.FindingsListOptions
	if isDatastar {
		var sig struct {
			Sev           string `json:"sev"`
			Kind          string `json:"kind"`
			Q             string `json:"q"`
			ShowCompliant bool   `json:"showCompliant"`
		}
		if err := datastar.ReadSignals(r, &sig); err == nil {
			opts.Severity = sig.Sev
			opts.Kind = sig.Kind
			opts.DomainQuery = strings.TrimSpace(sig.Q)
			opts.IncludeCompliant = sig.ShowCompliant
		}
	}

	res, err := h.svc.FindingsService().ListByTenant(r.Context(), p, opts)
	if err != nil {
		h.log.Error("findings: list by tenant", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	view := toTenantFindingsView(res)

	if isDatastar {
		sse := datastar.NewSSE(w, r)
		_ = sse.PatchElementTempl(
			templates.FindingsListFragment(view),
			datastar.WithSelectorID("findings-list"),
			datastar.WithModeInner(),
		)
		return
	}

	shell, err := h.shell(r.Context(), "findings")
	if err != nil {
		h.log.Error("findings: build shell", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	renderPage(w, r, templates.FindingsPage(templates.FindingsPageProps{
		Shell: shell,
		View:  view,
	}))
}

// toTenantFindingsView maps the service roll-up into the presentation model.
func toTenantFindingsView(res service.TenantFindingsResult) templates.TenantFindingsView {
	v := templates.TenantFindingsView{
		OpenCount:   res.Totals.Open,
		DomainCount: res.Totals.DomainCount,
		CritCount:   res.Totals.Critical,
		HighCount:   res.Totals.High,
		MedCount:    res.Totals.Medium,
		SevCounts:   res.SeverityCounts,
		KindOptions: kindOptions(res.KindCounts),
	}
	v.Groups = make([]templates.FindingGroupView, 0, len(res.Groups))
	for _, g := range res.Groups {
		v.Groups = append(v.Groups, toFindingGroupView(g))
	}
	return v
}

// findingKindOrder fixes the type-dropdown ordering; unknown future kinds are
// appended alphabetically so new assessors surface automatically.
var findingKindOrder = []string{"SPF", "DKIM", "DMARC", "ZONE", "CERT", "DNSSEC"}

var findingKindLabels = map[string]string{
	"SPF":    "SPF",
	"DKIM":   "DKIM",
	"DMARC":  "DMARC",
	"ZONE":   "Zone transfer",
	"CERT":   "Certificate",
	"DNSSEC": "DNSSEC",
}

// kindOptions builds the data-driven type dropdown from the faceted KindCounts.
func kindOptions(counts map[string]int) []templates.FindingKindOption {
	seen := make(map[string]bool, len(counts))
	out := make([]templates.FindingKindOption, 0, len(counts))
	add := func(k string) {
		label := k
		if l, ok := findingKindLabels[k]; ok {
			label = l
		}
		out = append(out, templates.FindingKindOption{Value: k, Label: label, Count: counts[k]})
		seen[k] = true
	}
	for _, k := range findingKindOrder {
		if counts[k] > 0 {
			add(k)
		}
	}
	extra := make([]string, 0)
	for k, c := range counts {
		if c > 0 && !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		add(k)
	}
	return out
}

// toFindingGroupView derives a group's dimmed-apex name, rollup bar, and pills.
func toFindingGroupView(g service.DomainFindingGroup) templates.FindingGroupView {
	label, apexSuffix := splitApexLabel(g.DomainName)
	gv := templates.FindingGroupView{
		DomainUID:  g.DomainUID,
		Name:       g.DomainName,
		Label:      label,
		ApexSuffix: apexSuffix,
		CountLabel: plural(len(g.Findings), "finding", "findings"),
		Segments:   rollupSegments(g),
		Pills:      rollupPills(g),
	}
	gv.Findings = make([]templates.FindingRowView, 0, len(g.Findings))
	for _, f := range g.Findings {
		gv.Findings = append(gv.Findings, toFindingRowView(f))
	}
	return gv
}

// splitApexLabel splits a domain into its bold leading label and dimmed apex
// suffix ("mail" + ".acme.com"). An apex domain renders fully bold (no suffix).
func splitApexLabel(name string) (label, apexSuffix string) {
	apex := apexOf(name)
	suffix := "." + apex
	if apex != "" && apex != name && strings.HasSuffix(name, suffix) {
		return strings.TrimSuffix(name, suffix), suffix
	}
	return name, ""
}

// tierSlice pairs the four actionable tiers with their seg/pill CSS letters in
// worst-first order, dropping the healthy "ok" tier from the rollup.
type tierSlice struct {
	class string // c | h | m | l
	glyph string // ● | ▲
	count int
}

func actionableTiers(g service.DomainFindingGroup) []tierSlice {
	return []tierSlice{
		{"c", "●", g.CritCount},
		{"h", "▲", g.HighCount},
		{"m", "▲", g.WarnCount},
		{"l", "▲", g.LowCount},
	}
}

// rollupSegments builds proportional seg-bar widths; the last present segment
// absorbs the rounding remainder so the bar always sums to 100%.
func rollupSegments(g service.DomainFindingGroup) []templates.FindingSegment {
	tiers := actionableTiers(g)
	total := 0
	for _, t := range tiers {
		total += t.count
	}
	if total == 0 {
		return nil
	}
	present := make([]tierSlice, 0, len(tiers))
	for _, t := range tiers {
		if t.count > 0 {
			present = append(present, t)
		}
	}
	segs := make([]templates.FindingSegment, 0, len(present))
	used := 0
	for i, t := range present {
		w := t.count * 100 / total
		if i == len(present)-1 {
			w = 100 - used
		}
		used += w
		segs = append(segs, templates.FindingSegment{Class: t.class, Width: strconv.Itoa(w) + "%"})
	}
	return segs
}

func rollupPills(g service.DomainFindingGroup) []templates.FindingPill {
	var pills []templates.FindingPill
	for _, t := range actionableTiers(g) {
		if t.count > 0 {
			pills = append(
				pills,
				templates.FindingPill{Class: t.class, Glyph: t.glyph, Count: t.count},
			)
		}
	}
	return pills
}

func toFindingRowView(f service.FindingView) templates.FindingRowView {
	return templates.FindingRowView{
		FindingUID:  f.FindingUID,
		DomainUID:   f.DomainUID,
		Tier:        f.Tier,
		Severity:    f.Severity,
		Kind:        f.Kind,
		Icon:        f.Icon,
		Title:       f.Title,
		Description: f.Description,
		Evidence:    f.Evidence,
		FixHint:     f.FixHint,
		FirstSeen:   f.FirstSeen,
	}
}
