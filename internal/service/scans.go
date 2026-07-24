package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const scanRowLimit = 200

type ScansService struct {
	*Service
}

type ScansListOptions struct {
	Source      string
	DomainQuery string
	WindowDays  int
	ChangedOnly bool
}

type ScanChange struct {
	EntityType string
	ChangeType string
	Op         string
	Class      string
	Count      int
}

type ScanSegment struct {
	Class string
	Width string
}

type ScanPill struct {
	Class string
	Glyph string
	Count int
}

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

type ScanDayGroup struct {
	DayKey   string
	DayLabel string
	DayDate  string
	Scans    []ScanRunView
}

type ScanTotals struct {
	ScanCount   int
	ChangeCount int
	DomainCount int
	CleanCount  int
}

type TenantScansResult struct {
	SourceCounts map[string]int
	Days         []ScanDayGroup
	Totals       ScanTotals
}

type FlatScanView struct {
	StartedAt     time.Time
	ScanUID       string
	DomainUID     string
	DomainName    string
	Source        string
	ParentScanUID string
	State         string
	Changes       []ScanChange
	CreatedCount  int
	UpdatedCount  int
	DeletedCount  int
	TotalChanges  int
	IsBaseline    bool
}

type FlatScansResult struct {
	Scans      []FlatScanView
	TotalCount int64
}

type ScanObservationDetail struct {
	ObservedAt time.Time
	EntityType string
	EntityKey  string
	ChangeType string
	Payload    json.RawMessage
}

type ScanDetailView struct {
	Observations []ScanObservationDetail
	FlatScanView
}

func (s *ScansService) GetByUID(
	ctx context.Context,
	p *auth.Principal,
	uid string,
) (ScanDetailView, error) {
	row, err := s.DB.ScansGetByTenantUID(ctx, store.ScansGetByTenantUIDParams{
		TenantID: p.TenantID,
		Uid:      uid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ScanDetailView{}, ErrNotFound
		}
		return ScanDetailView{}, fmt.Errorf("get scan: %w", err)
	}

	head := flatScanView(mapScanRow(store.ScansListByTenantRow{
		ScanUid:       row.ScanUid,
		DomainUid:     row.DomainUid,
		DomainName:    row.DomainName,
		Source:        row.Source,
		StartedAt:     row.StartedAt,
		ParentScanUid: row.ParentScanUid,
		CreatedCount:  row.CreatedCount,
		UpdatedCount:  row.UpdatedCount,
		DeletedCount:  row.DeletedCount,
		Breakdown:     row.Breakdown,
	}, time.Now()))

	obsRows, err := s.DB.ObservationsListByScan(ctx, store.ObservationsListByScanParams{
		ScanID:   pgtype.Int8{Int64: row.ScanID, Valid: true},
		TenantID: p.TenantID,
	})
	if err != nil {
		return ScanDetailView{}, fmt.Errorf("list scan observations: %w", err)
	}

	observations := make([]ScanObservationDetail, 0, len(obsRows))
	for _, o := range obsRows {
		observations = append(observations, ScanObservationDetail{
			EntityType: o.EntityType,
			EntityKey:  o.EntityKey,
			ChangeType: o.ChangeType,
			Payload:    json.RawMessage(o.Payload),
			ObservedAt: o.ObservedAt.Time,
		})
	}

	return ScanDetailView{FlatScanView: head, Observations: observations}, nil
}

func (s *ScansService) ListByTenantFlat(
	ctx context.Context,
	p *auth.Principal,
	opts ScansListOptions,
	pageSize, offset int32,
) (FlatScansResult, error) {
	grouped, err := s.ListByTenant(ctx, p, opts)
	if err != nil {
		return FlatScansResult{}, err
	}

	var all []FlatScanView
	for _, day := range grouped.Days {
		for _, v := range day.Scans {
			all = append(all, flatScanView(v))
		}
	}

	total := int64(len(all))
	lo := int(offset)
	if lo > len(all) {
		lo = len(all)
	}
	hi := lo + int(pageSize)
	if hi > len(all) {
		hi = len(all)
	}
	return FlatScansResult{Scans: all[lo:hi], TotalCount: total}, nil
}

func flatScanView(v ScanRunView) FlatScanView {
	return FlatScanView{
		StartedAt:     v.StartedAt,
		ScanUID:       v.ScanUID,
		DomainUID:     v.DomainUID,
		DomainName:    v.DomainName,
		Source:        v.Source,
		ParentScanUID: v.ParentScanUID,
		State:         v.State,
		Changes:       v.Changes,
		CreatedCount:  v.CreatedCount,
		UpdatedCount:  v.UpdatedCount,
		DeletedCount:  v.DeletedCount,
		TotalChanges:  v.TotalChanges,
		IsBaseline:    v.IsBaseline,
	}
}

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

type scanChangeKind struct {
	class string
	glyph string
	count int
}

func scanChangeKinds(created, updated, deleted int) []scanChangeKind {
	return []scanChangeKind{
		{"c", "+", created},
		{"u", "~", updated},
		{"d", "−", deleted},
	}
}

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

func scanPills(created, updated, deleted int) []ScanPill {
	var pills []ScanPill
	for _, k := range scanChangeKinds(created, updated, deleted) {
		if k.count > 0 {
			pills = append(pills, ScanPill{Class: k.class, Glyph: k.glyph, Count: k.count})
		}
	}
	return pills
}

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
