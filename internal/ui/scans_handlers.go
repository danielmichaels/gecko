package ui

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/ui/templates"
	datastar "github.com/starfederation/datastar-go/datastar"
)

// defaultScanWindowDays mirrors the page's default $win signal ("7") so the
// initial full-page render and the select control agree.
const defaultScanWindowDays = 7

// handleScansPage renders the tenant-wide scan feed. The same route serves the
// full page (browser nav) and a fragment (#scans-list) on every filter change,
// which datastar tags with the Datastar-Request header.
func (h *Handlers) handleScansPage(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	isDatastar := r.Header.Get("Datastar-Request") == "true"

	opts := service.ScansListOptions{WindowDays: defaultScanWindowDays}
	if isDatastar {
		var sig struct {
			Src         string `json:"src"`
			Q           string `json:"q"`
			Win         string `json:"win"`
			ChangedOnly bool   `json:"changedOnly"`
		}
		if err := datastar.ReadSignals(r, &sig); err == nil {
			opts.Source = sig.Src
			opts.DomainQuery = strings.TrimSpace(sig.Q)
			opts.ChangedOnly = sig.ChangedOnly
			opts.WindowDays = parseWindowDays(sig.Win)
		}
	}

	res, err := h.svc.ScansService().ListByTenant(r.Context(), p, opts)
	if err != nil {
		h.log.Error("scans: list by tenant", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	view := toTenantScansView(res)

	if isDatastar {
		sse := datastar.NewSSE(w, r)
		_ = sse.PatchElementTempl(
			templates.ScansListFragment(view),
			datastar.WithSelectorID("scans-list"),
			datastar.WithModeInner(),
		)
		return
	}

	shell, err := h.shell(r.Context(), "scans")
	if err != nil {
		h.log.Error("scans: build shell", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	renderPage(w, r, templates.ScansPage(templates.ScansPageProps{
		Shell: shell,
		View:  view,
	}))
}

// parseWindowDays maps the $win select value to a day count. An empty or invalid
// value falls back to the default window; "0" means all-time.
func parseWindowDays(win string) int {
	if win == "" {
		return defaultScanWindowDays
	}
	n, err := strconv.Atoi(win)
	if err != nil || n < 0 {
		return defaultScanWindowDays
	}
	return n
}

// toTenantScansView maps the service feed into the presentation model.
func toTenantScansView(res service.TenantScansResult) templates.TenantScansView {
	v := templates.TenantScansView{
		ScanCount:     res.Totals.ScanCount,
		DomainCount:   res.Totals.DomainCount,
		ChangeCount:   res.Totals.ChangeCount,
		CleanCount:    res.Totals.CleanCount,
		SourceOptions: sourceOptions(res.SourceCounts),
	}
	v.Days = make([]templates.ScanDayGroupView, 0, len(res.Days))
	for _, d := range res.Days {
		dv := templates.ScanDayGroupView{Label: d.DayLabel, Date: d.DayDate}
		dv.Scans = make([]templates.ScanRowView, 0, len(d.Scans))
		for _, s := range d.Scans {
			dv.Scans = append(dv.Scans, toScanRowView(s))
		}
		v.Days = append(v.Days, dv)
	}
	return v
}

// scanSourceOrder fixes the source-chip ordering; unknown future sources are
// appended so a new scan_source value surfaces automatically.
var scanSourceOrder = []string{"user_supplied", "discovered", "scheduled"}

// The class tokens are namespaced ("src-*") so they cannot match the global
// .disc/.user rules — .disc is the timeline disclosure caret (a 16px grid square),
// and a bare "disc" token on the source badge/chip would inherit that and collapse.
var scanSourceMeta = map[string]struct{ class, label string }{
	"user_supplied": {"src-user", "User"},
	"discovered":    {"src-disc", "Discovered"},
	"scheduled":     {"src-sched", "Scheduled"},
}

// sourceOptions builds the data-driven source chips from the faceted SourceCounts.
func sourceOptions(counts map[string]int) []templates.ScanSourceOption {
	seen := make(map[string]bool, len(counts))
	out := make([]templates.ScanSourceOption, 0, len(counts))
	add := func(v string) {
		meta, ok := scanSourceMeta[v]
		if !ok {
			meta = struct{ class, label string }{"src-disc", v}
		}
		out = append(out, templates.ScanSourceOption{
			Value: v, Class: meta.class, Label: meta.label, Count: counts[v],
		})
		seen[v] = true
	}
	for _, v := range scanSourceOrder {
		if counts[v] > 0 {
			add(v)
		}
	}
	for v, c := range counts {
		if c > 0 && !seen[v] {
			add(v)
		}
	}
	return out
}

// toScanRowView maps a service scan view to its presentation row, splitting the
// dimmed apex and precomputing the diff/meta text the template renders verbatim.
func toScanRowView(s service.ScanRunView) templates.ScanRowView {
	label, apexSuffix := splitApexLabel(s.DomainName)
	row := templates.ScanRowView{
		ScanUID:       s.ScanUID,
		DomainUID:     s.DomainUID,
		Label:         label,
		ApexSuffix:    apexSuffix,
		SourceClass:   scanSourceClass(s.Source),
		SourceLabel:   s.SourceLabel,
		State:         s.State,
		AbsoluteTime:  s.AbsoluteTime,
		RelativeTime:  s.RelativeTime,
		ParentScanUID: s.ParentScanUID,
		DeltaMeta:     scanDeltaMeta(s),
		TimelineURL:   s.TimelineURL,
		IsBaseline:    s.IsBaseline,
	}
	if !s.IsBaseline && s.ParentScanUID != "" {
		row.ParentURL = fmt.Sprintf(
			"/app/domains/%s?tab=timeline&scan=%s", s.DomainUID, s.ParentScanUID,
		)
	}

	switch s.State {
	case "clean":
		row.CleanMessage = fmt.Sprintf(
			"Nothing changed since the previous scan — all records and findings match %s.",
			s.ParentScanUID,
		)
	case "baseline":
		row.DeltaHead = fmt.Sprintf("baseline — %d records first observed", s.TotalChanges)
	default:
		row.DeltaHead = plural(s.TotalChanges, "change", "changes") + " since " + s.ParentScanUID
	}

	row.Segments = make([]templates.ScanSegment, 0, len(s.Segments))
	for _, seg := range s.Segments {
		row.Segments = append(
			row.Segments,
			templates.ScanSegment{Class: seg.Class, Width: seg.Width},
		)
	}
	row.Pills = make([]templates.ScanPill, 0, len(s.Pills))
	for _, pill := range s.Pills {
		row.Pills = append(
			row.Pills,
			templates.ScanPill{Class: pill.Class, Glyph: pill.Glyph, Count: pill.Count},
		)
	}
	row.Changes = make([]templates.ScanChangeView, 0, len(s.Changes))
	for _, c := range s.Changes {
		row.Changes = append(row.Changes, templates.ScanChangeView{
			Class:      c.Class,
			Op:         c.Op,
			EntityType: c.EntityType,
			CountLabel: fmt.Sprintf("%d %s", c.Count, c.ChangeType),
		})
	}
	return row
}

// scanDeltaMeta renders the detail footer's scan-meta line. Baseline scans are
// annotated "no parent".
func scanDeltaMeta(s service.ScanRunView) string {
	meta := s.ScanUID + " · " + s.FullTime
	if s.IsBaseline {
		meta += " · no parent"
	}
	return meta
}

// scanSourceClass maps the domain_source enum to its row-badge CSS class.
func scanSourceClass(source string) string {
	if meta, ok := scanSourceMeta[source]; ok {
		return meta.class
	}
	return "src-disc"
}
