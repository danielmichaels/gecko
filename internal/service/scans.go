package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// scanRowLimit caps how many windowed scans the tenant feed aggregates in a
// single page. It bounds the observation aggregation (the SQL only sums
// observations for these scans) and the DOM. ListByTenant logs when it truncates
// so the feed never silently implies it is exhaustive.
const scanRowLimit = 200

// ScansService exposes the tenant-wide reverse-chronological scan feed.
type ScansService struct {
	*Service
}

// ScansListOptions narrows a tenant-wide scan listing. Empty strings mean "no
// filter". Source is an exact match on the domain_source enum; DomainQuery is a
// case-insensitive substring on the domain name; WindowDays bounds how far back
// the feed reaches (0 = all-time); ChangedOnly hides clean scans (baselines stay).
type ScansListOptions struct {
	Source      string
	DomainQuery string
	WindowDays  int
	ChangedOnly bool
}

// ScanChange is one entity_type rollup within a scan's diff, presentation-ready.
// Op/Class encode the change kind: created -> +/c, updated -> ~/u, deleted -> −/d.
type ScanChange struct {
	EntityType string
	ChangeType string
	Op         string
	Class      string
	Count      int
}

// ScanSegment is one proportional slice of a scan's change seg-bar.
type ScanSegment struct {
	Class string // c | u | d
	Width string // e.g. "34%"
}

// ScanPill is one per-change-kind count chip on a scan row.
type ScanPill struct {
	Class string // c | u | d
	Glyph string // + | ~ | −
	Count int
}

// ScanRunView is one scan run rendered as a feed row. State drives the timeline
// node-dot and the summary cell: "baseline" (first observation, no parent),
// "clean" (a re-scan that changed nothing), or "changed".
type ScanRunView struct {
	StartedAt     time.Time
	ScanUID       string
	DomainUID     string
	DomainName    string
	Source        string
	SourceLabel   string
	ParentScanUID string
	State         string
	RelativeTime  string
	AbsoluteTime  string
	FullTime      string
	TimelineURL   string
	Segments      []ScanSegment
	Pills         []ScanPill
	Changes       []ScanChange
	CreatedCount  int
	UpdatedCount  int
	DeletedCount  int
	TotalChanges  int
	IsBaseline    bool
}

// ScanDayGroup is one day bucket on the timeline spine, newest day first.
type ScanDayGroup struct {
	DayKey   string // "2006-01-02" (UTC) — group identity
	DayLabel string // "Today" | "Yesterday" | weekday ("Mon")
	DayDate  string // dimmed date, e.g. "09 Jun"
	Scans    []ScanRunView
}

// ScanTotals drives the stat strip; counts reflect the fully-filtered view.
type ScanTotals struct {
	ScanCount   int
	ChangeCount int
	DomainCount int
	CleanCount  int
}

// TenantScansResult is the tenant-wide feed: day-grouped scan runs, the totals
// strip, and the faceted source counts for the filter chips. SourceCounts ignores
// the active Source filter so both chips stay populated as the user narrows.
type TenantScansResult struct {
	SourceCounts map[string]int
	Days         []ScanDayGroup
	Totals       ScanTotals
}

// ListByTenant returns the tenant's reverse-chronological scan feed with per-scan
// change aggregates. Tenant isolation is the WHERE s.tenant_id gate inside
// ScansListByTenant — never a Go-side filter.
func (s *ScansService) ListByTenant(
	ctx context.Context,
	p *auth.Principal,
	opts ScansListOptions,
) (TenantScansResult, error) {
	now := time.Now()
	var since pgtype.Timestamptz
	if opts.WindowDays > 0 {
		since = pgtype.Timestamptz{
			Time:  now.Add(-time.Duration(opts.WindowDays) * 24 * time.Hour),
			Valid: true,
		}
	}

	rows, err := s.DB.ScansListByTenant(ctx, store.ScansListByTenantParams{
		TenantID: p.TenantID,
		Since:    since,
		RowLimit: scanRowLimit,
	})
	if err != nil {
		return TenantScansResult{}, err
	}
	if len(rows) == scanRowLimit {
		s.Log.Warn(
			"scans feed truncated at row_limit: older scans in the window are not shown",
			"tenant", p.TenantID, "cap", scanRowLimit,
		)
	}

	return buildTenantScans(rows, opts, now), nil
}

// buildTenantScans is the pure grouping/filter/derive layer over the raw rows
// (which arrive newest-first). Separated from the DB call so it is exhaustively
// unit-testable with synthetic rows and an injected clock.
func buildTenantScans(
	rows []store.ScansListByTenantRow,
	opts ScansListOptions,
	now time.Time,
) TenantScansResult {
	res := TenantScansResult{SourceCounts: map[string]int{}}
	query := strings.ToLower(strings.TrimSpace(opts.DomainQuery))
	domainSeen := make(map[string]struct{}, len(rows))
	dayIndex := make(map[string]int, len(rows))

	for _, row := range rows {
		v := mapScanRow(row, now)

		if query != "" && !strings.Contains(strings.ToLower(v.DomainName), query) {
			continue
		}
		// Faceted: the source chip ignores its own filter so both chips stay
		// populated as the domain search narrows.
		res.SourceCounts[v.Source]++

		if opts.Source != "" && v.Source != opts.Source {
			continue
		}
		if opts.ChangedOnly && v.State == "clean" {
			continue
		}

		res.Totals.ScanCount++
		res.Totals.ChangeCount += v.TotalChanges
		if v.State == "clean" {
			res.Totals.CleanCount++
		}
		domainSeen[v.DomainUID] = struct{}{}

		key, label, date := dayBucket(now, v.StartedAt)
		di, ok := dayIndex[key]
		if !ok {
			di = len(res.Days)
			dayIndex[key] = di
			res.Days = append(res.Days, ScanDayGroup{DayKey: key, DayLabel: label, DayDate: date})
		}
		res.Days[di].Scans = append(res.Days[di].Scans, v)
	}
	res.Totals.DomainCount = len(domainSeen)
	return res
}

// mapScanRow maps one aggregated SQL row to a presentation-ready scan view.
func mapScanRow(row store.ScansListByTenantRow, now time.Time) ScanRunView {
	started := row.StartedAt.Time
	isBaseline := !row.ParentScanUid.Valid || row.ParentScanUid.String == ""
	created, updated, deleted := int(row.CreatedCount), int(row.UpdatedCount), int(row.DeletedCount)
	total := created + updated + deleted

	state := "changed"
	switch {
	case isBaseline:
		state = "baseline"
	case total == 0:
		state = "clean"
	}

	return ScanRunView{
		ScanUID:       row.ScanUid,
		DomainUID:     row.DomainUid,
		DomainName:    row.DomainName,
		Source:        string(row.Source),
		SourceLabel:   sourceLabel(string(row.Source)),
		ParentScanUID: row.ParentScanUid.String,
		State:         state,
		StartedAt:     started,
		RelativeTime:  relativeSince(now, started),
		AbsoluteTime:  started.UTC().Format("15:04"),
		FullTime:      started.UTC().Format("2006-01-02 15:04:05 MST"),
		IsBaseline:    isBaseline,
		CreatedCount:  created,
		UpdatedCount:  updated,
		DeletedCount:  deleted,
		TotalChanges:  total,
		Segments:      scanSegments(created, updated, deleted),
		Pills:         scanPills(created, updated, deleted),
		Changes:       scanChanges(row.Breakdown),
		TimelineURL: fmt.Sprintf(
			"/app/domains/%s?tab=timeline&scan=%s",
			row.DomainUid,
			row.ScanUid,
		),
	}
}

// sourceLabel renders the domain_source enum as its badge text.
func sourceLabel(source string) string {
	switch source {
	case string(store.DomainSourceUserSupplied):
		return "user"
	case string(store.DomainSourceDiscovered):
		return "discovered"
	default:
		return source
	}
}

// dayBucket assigns a scan to a UTC day bucket and renders its divider labels.
// Day boundaries are server-side UTC for v1 (deterministic, test-friendly);
// per-user timezone is out of scope.
func dayBucket(now, t time.Time) (key, label, date string) {
	tu, nu := t.UTC(), now.UTC()
	key = tu.Format("2006-01-02")
	date = tu.Format("02 Jan")

	startOfDay := func(x time.Time) time.Time {
		return time.Date(x.Year(), x.Month(), x.Day(), 0, 0, 0, 0, time.UTC)
	}
	days := int(startOfDay(nu).Sub(startOfDay(tu)).Hours() / 24)
	switch days {
	case 0:
		label = "Today"
	case 1:
		label = "Yesterday"
	default:
		label = tu.Format("Mon")
	}
	return key, label, date
}

// relativeSince renders a human "Nm ago" string against the injected clock,
// mirroring ui.relativeTime but with an injectable now for deterministic tests.
func relativeSince(now, t time.Time) string {
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(math.Round(d.Minutes()))) + "m ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(math.Round(d.Hours()))) + "h ago"
	case d < 7*24*time.Hour:
		return strconv.Itoa(int(math.Round(d.Hours()/24))) + "d ago"
	default:
		return t.UTC().Format("2006-01-02")
	}
}

// scanChangeKind pairs a change kind with its seg/pill CSS class and op glyph.
type scanChangeKind struct {
	class string // c | u | d
	glyph string // + | ~ | −
	count int
}

func scanChangeKinds(created, updated, deleted int) []scanChangeKind {
	return []scanChangeKind{
		{"c", "+", created},
		{"u", "~", updated},
		{"d", "−", deleted},
	}
}

// scanSegments builds proportional seg-bar widths over the present change kinds;
// the last present segment absorbs the rounding remainder so widths sum to 100%.
func scanSegments(created, updated, deleted int) []ScanSegment {
	total := created + updated + deleted
	if total == 0 {
		return nil
	}
	present := make([]scanChangeKind, 0, 3)
	for _, k := range scanChangeKinds(created, updated, deleted) {
		if k.count > 0 {
			present = append(present, k)
		}
	}
	segs := make([]ScanSegment, 0, len(present))
	used := 0
	for i, k := range present {
		w := k.count * 100 / total
		if i == len(present)-1 {
			w = 100 - used
		}
		used += w
		segs = append(segs, ScanSegment{Class: k.class, Width: strconv.Itoa(w) + "%"})
	}
	return segs
}

// scanPills builds one count chip per present change kind, worst-neutral order
// created/updated/deleted.
func scanPills(created, updated, deleted int) []ScanPill {
	var pills []ScanPill
	for _, k := range scanChangeKinds(created, updated, deleted) {
		if k.count > 0 {
			pills = append(pills, ScanPill{Class: k.class, Glyph: k.glyph, Count: k.count})
		}
	}
	return pills
}

// scanChanges unmarshals the jsonb breakdown into presentation-ready changes,
// mapped to op/class and sorted stably by entity type then change kind.
func scanChanges(raw []byte) []ScanChange {
	if len(raw) == 0 {
		return nil
	}
	var items []struct {
		EntityType string `json:"entity_type"`
		ChangeType string `json:"change_type"`
		Count      int    `json:"count"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	out := make([]ScanChange, 0, len(items))
	for _, it := range items {
		op, class := changeOpClass(it.ChangeType)
		out = append(out, ScanChange{
			EntityType: it.EntityType,
			ChangeType: it.ChangeType,
			Op:         op,
			Class:      class,
			Count:      it.Count,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].EntityType != out[j].EntityType {
			return out[i].EntityType < out[j].EntityType
		}
		return classRank(out[i].Class) < classRank(out[j].Class)
	})
	return out
}

// changeOpClass maps an observation change_type to its op glyph and CSS class.
func changeOpClass(changeType string) (op, class string) {
	switch changeType {
	case "created":
		return "+", "c"
	case "deleted":
		return "−", "d"
	default:
		return "~", "u"
	}
}

// classRank fixes the within-entity display order: created, updated, deleted.
func classRank(class string) int {
	switch class {
	case "c":
		return 0
	case "u":
		return 1
	default:
		return 2
	}
}
