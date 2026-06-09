package service

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// changeSpec is one entity_type/change_type/count tuple in a scan's breakdown.
type changeSpec struct {
	entityType string
	changeType string
	count      int
}

// scanRow builds a synthetic ScansListByTenantRow for the pure builder tests. The
// created/updated/deleted aggregate columns are derived from breakdown so the row
// is internally consistent (as the SQL guarantees). An empty parentUID yields a
// baseline (NULL parent).
func scanRow(
	t *testing.T,
	scanUID, domainUID, name, source, parentUID string,
	started time.Time,
	breakdown []changeSpec,
) store.ScansListByTenantRow {
	t.Helper()
	var created, updated, deleted int
	raw := make([]map[string]any, 0, len(breakdown))
	for _, c := range breakdown {
		switch c.changeType {
		case "created":
			created += c.count
		case "updated":
			updated += c.count
		case "deleted":
			deleted += c.count
		}
		raw = append(raw, map[string]any{
			"entity_type": c.entityType,
			"change_type": c.changeType,
			"count":       c.count,
		})
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal breakdown: %v", err)
	}
	if len(breakdown) == 0 {
		payload = []byte("[]")
	}
	return store.ScansListByTenantRow{
		ScanUid:       scanUID,
		DomainUid:     domainUID,
		DomainName:    name,
		Source:        store.DomainSource(source),
		StartedAt:     pgtype.Timestamptz{Time: started, Valid: true},
		ParentScanUid: pgtype.Text{String: parentUID, Valid: parentUID != ""},
		CreatedCount:  int32(created),
		UpdatedCount:  int32(updated),
		DeletedCount:  int32(deleted),
		Breakdown:     payload,
	}
}

// fixedNow is the injected clock for deterministic day labels / relative times.
var fixedNow = time.Date(2026, time.June, 9, 15, 0, 0, 0, time.UTC)

func allScans(res TenantScansResult) []ScanRunView {
	var out []ScanRunView
	for _, d := range res.Days {
		out = append(out, d.Scans...)
	}
	return out
}

func TestBuildTenantScans_DayGroupingAndOrder(t *testing.T) {
	today := time.Date(2026, time.June, 9, 14, 38, 0, 0, time.UTC)
	earlierToday := time.Date(2026, time.June, 9, 9, 15, 0, 0, time.UTC)
	yesterday := time.Date(2026, time.June, 8, 18, 44, 0, 0, time.UTC)
	older := time.Date(2026, time.June, 2, 10, 0, 0, 0, time.UTC)

	// Rows arrive newest-first (as the SQL ORDER BY guarantees).
	rows := []store.ScansListByTenantRow{
		scanRow(t, "scan_a", "d1", "acme.com", "user_supplied", "scan_z", today,
			[]changeSpec{{"a_record", "created", 1}}),
		scanRow(t, "scan_b", "d2", "legacy.test.io", "user_supplied", "scan_q", earlierToday,
			[]changeSpec{{"ns_record", "created", 2}}),
		scanRow(t, "scan_c", "d3", "blog.example.org", "discovered", "", yesterday,
			[]changeSpec{{"a_record", "created", 14}}),
		scanRow(t, "scan_d", "d1", "acme.com", "user_supplied", "scan_y", older, nil),
	}

	got := buildTenantScans(rows, ScansListOptions{}, fixedNow)

	if len(got.Days) != 3 {
		t.Fatalf("day groups = %d, want 3", len(got.Days))
	}
	// 2026-06-02 is a Tuesday — older buckets render the weekday abbreviation.
	wantLabels := []string{"Today", "Yesterday", "Tue"}
	for i, w := range wantLabels {
		if got.Days[i].DayLabel != w {
			t.Errorf("Days[%d].DayLabel = %q, want %q", i, got.Days[i].DayLabel, w)
		}
	}
	// Within Today, newest-first order preserved: scan_a (14:38) before scan_b (09:15).
	if len(got.Days[0].Scans) != 2 {
		t.Fatalf("today scans = %d, want 2", len(got.Days[0].Scans))
	}
	if got.Days[0].Scans[0].ScanUID != "scan_a" || got.Days[0].Scans[1].ScanUID != "scan_b" {
		t.Errorf("today order = [%s %s], want [scan_a scan_b]",
			got.Days[0].Scans[0].ScanUID, got.Days[0].Scans[1].ScanUID)
	}
	if got.Days[0].DayDate != "09 Jun" {
		t.Errorf("today DayDate = %q, want %q", got.Days[0].DayDate, "09 Jun")
	}
}

func TestBuildTenantScans_State(t *testing.T) {
	today := time.Date(2026, time.June, 9, 12, 0, 0, 0, time.UTC)
	rows := []store.ScansListByTenantRow{
		scanRow(t, "scan_changed", "d1", "a.com", "user_supplied", "scan_p", today,
			[]changeSpec{{"a_record", "created", 1}}),
		scanRow(t, "scan_clean", "d2", "b.com", "discovered", "scan_o", today, nil),
		scanRow(t, "scan_base", "d3", "c.com", "discovered", "", today,
			[]changeSpec{{"a_record", "created", 4}}),
	}

	got := buildTenantScans(rows, ScansListOptions{}, fixedNow)
	byUID := map[string]ScanRunView{}
	for _, s := range allScans(got) {
		byUID[s.ScanUID] = s
	}

	if s := byUID["scan_changed"]; s.State != "changed" || s.IsBaseline {
		t.Errorf("changed: State=%q IsBaseline=%v, want changed/false", s.State, s.IsBaseline)
	}
	if s := byUID["scan_clean"]; s.State != "clean" || s.TotalChanges != 0 {
		t.Errorf("clean: State=%q Total=%d, want clean/0", s.State, s.TotalChanges)
	}
	if s := byUID["scan_base"]; s.State != "baseline" || !s.IsBaseline {
		t.Errorf("baseline: State=%q IsBaseline=%v, want baseline/true", s.State, s.IsBaseline)
	}

	if got.Totals.ScanCount != 3 || got.Totals.ChangeCount != 5 {
		t.Errorf(
			"Totals scan/change = %d/%d, want 3/5",
			got.Totals.ScanCount,
			got.Totals.ChangeCount,
		)
	}
	if got.Totals.DomainCount != 3 || got.Totals.CleanCount != 1 {
		t.Errorf(
			"Totals domain/clean = %d/%d, want 3/1",
			got.Totals.DomainCount,
			got.Totals.CleanCount,
		)
	}
}

func TestBuildTenantScans_SegmentsAndPills(t *testing.T) {
	today := time.Date(2026, time.June, 9, 12, 0, 0, 0, time.UTC)
	rows := []store.ScansListByTenantRow{
		scanRow(t, "scan_a", "d1", "a.com", "user_supplied", "scan_p", today,
			[]changeSpec{
				{"a_record", "created", 1},
				{"mx_record", "updated", 1},
				{"txt_record", "deleted", 1},
			}),
	}
	got := buildTenantScans(rows, ScansListOptions{}, fixedNow)
	s := allScans(got)[0]

	// Three equal segments, widths sum to 100 with the last absorbing the remainder.
	if len(s.Segments) != 3 {
		t.Fatalf("segments = %d, want 3", len(s.Segments))
	}
	sum := 0
	for _, seg := range s.Segments {
		n, err := strconv.Atoi(strings.TrimSuffix(seg.Width, "%"))
		if err != nil {
			t.Fatalf("bad width %q: %v", seg.Width, err)
		}
		sum += n
	}
	if sum != 100 {
		t.Errorf("segment widths sum = %d, want 100 (%+v)", sum, s.Segments)
	}
	wantClasses := []string{"c", "u", "d"}
	for i, w := range wantClasses {
		if s.Segments[i].Class != w {
			t.Errorf("Segments[%d].Class = %q, want %q", i, s.Segments[i].Class, w)
		}
	}
	if len(s.Pills) != 3 {
		t.Fatalf("pills = %d, want 3", len(s.Pills))
	}
	if s.Pills[0].Glyph != "+" || s.Pills[1].Glyph != "~" || s.Pills[2].Glyph != "−" {
		t.Errorf("pill glyphs = [%s %s %s], want [+ ~ −]",
			s.Pills[0].Glyph, s.Pills[1].Glyph, s.Pills[2].Glyph)
	}
}

func TestBuildTenantScans_ChangesUnmarshalledAndMapped(t *testing.T) {
	today := time.Date(2026, time.June, 9, 12, 0, 0, 0, time.UTC)
	rows := []store.ScansListByTenantRow{
		scanRow(t, "scan_a", "d1", "a.com", "user_supplied", "scan_p", today,
			[]changeSpec{
				{"mx_record", "updated", 2},
				{"a_record", "created", 1},
			}),
	}
	got := buildTenantScans(rows, ScansListOptions{}, fixedNow)
	s := allScans(got)[0]

	if len(s.Changes) != 2 {
		t.Fatalf("changes = %d, want 2", len(s.Changes))
	}
	// Sorted stably by entity_type: a_record before mx_record.
	if s.Changes[0].EntityType != "a_record" || s.Changes[1].EntityType != "mx_record" {
		t.Errorf("change order = [%s %s], want [a_record mx_record]",
			s.Changes[0].EntityType, s.Changes[1].EntityType)
	}
	if s.Changes[0].Op != "+" || s.Changes[0].Class != "c" || s.Changes[0].Count != 1 {
		t.Errorf("created change = %+v, want +/c/1", s.Changes[0])
	}
	if s.Changes[1].Op != "~" || s.Changes[1].Class != "u" || s.Changes[1].Count != 2 {
		t.Errorf("updated change = %+v, want ~/u/2", s.Changes[1])
	}
}

func TestBuildTenantScans_Filters(t *testing.T) {
	today := time.Date(2026, time.June, 9, 12, 0, 0, 0, time.UTC)
	rows := []store.ScansListByTenantRow{
		scanRow(t, "scan_a", "d1", "acme.com", "user_supplied", "scan_p", today,
			[]changeSpec{{"a_record", "created", 1}}),
		scanRow(t, "scan_b", "d2", "shop.example.org", "discovered", "scan_q", today, nil),
		scanRow(t, "scan_c", "d3", "blog.example.org", "discovered", "", today,
			[]changeSpec{{"a_record", "created", 4}}),
	}

	t.Run("source exact match", func(t *testing.T) {
		got := buildTenantScans(rows, ScansListOptions{Source: "discovered"}, fixedNow)
		if got.Totals.ScanCount != 2 {
			t.Errorf("scans = %d, want 2 (two discovered)", got.Totals.ScanCount)
		}
		// SourceCounts faceted: ignores the source filter so both chips stay populated.
		if got.SourceCounts["user_supplied"] != 1 || got.SourceCounts["discovered"] != 2 {
			t.Errorf("SourceCounts not faceted: %v", got.SourceCounts)
		}
	})

	t.Run("domain substring case-insensitive", func(t *testing.T) {
		got := buildTenantScans(rows, ScansListOptions{DomainQuery: "EXAMPLE.ORG"}, fixedNow)
		if got.Totals.ScanCount != 2 {
			t.Errorf("scans = %d, want 2", got.Totals.ScanCount)
		}
	})

	t.Run("changedOnly drops clean but keeps baseline", func(t *testing.T) {
		got := buildTenantScans(rows, ScansListOptions{ChangedOnly: true}, fixedNow)
		uids := map[string]bool{}
		for _, s := range allScans(got) {
			uids[s.ScanUID] = true
		}
		if uids["scan_b"] {
			t.Errorf("changedOnly kept clean scan_b")
		}
		if !uids["scan_a"] || !uids["scan_c"] {
			t.Errorf("changedOnly dropped changed/baseline: %v", uids)
		}
	})
}

func TestBuildTenantScans_TimelineURL(t *testing.T) {
	today := time.Date(2026, time.June, 9, 12, 0, 0, 0, time.UTC)
	rows := []store.ScansListByTenantRow{
		scanRow(t, "scan_a1b2", "dom_xyz", "acme.com", "user_supplied", "scan_p", today, nil),
	}
	got := buildTenantScans(rows, ScansListOptions{}, fixedNow)
	s := allScans(got)[0]
	want := "/app/domains/dom_xyz?tab=timeline&scan=scan_a1b2"
	if s.TimelineURL != want {
		t.Errorf("TimelineURL = %q, want %q", s.TimelineURL, want)
	}
}

func TestBuildTenantScans_Empty(t *testing.T) {
	got := buildTenantScans(nil, ScansListOptions{}, fixedNow)
	if len(got.Days) != 0 {
		t.Errorf("days = %d, want 0", len(got.Days))
	}
	if got.Totals != (ScanTotals{}) {
		t.Errorf("totals = %+v, want zero value", got.Totals)
	}
}
