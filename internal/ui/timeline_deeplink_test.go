package ui

import (
	"testing"

	"github.com/danielmichaels/gecko/internal/dto"
)

func TestTimelineFullView_HighlightsTargetScan(t *testing.T) {
	scans := []dto.ScanDiff{
		{ScanUID: "scan_a", Source: "user_supplied", StartedAt: "2026-06-09T14:38:00Z"},
		{ScanUID: "scan_b", Source: "discovered", StartedAt: "2026-06-08T10:00:00Z"},
	}

	t.Run("matching scan is highlighted, others are not", func(t *testing.T) {
		v := timelineFullView(scans, "scan_b")
		for _, g := range v.Groups {
			want := g.ScanID == "scan_b"
			if g.Highlighted != want {
				t.Errorf("group %s Highlighted=%v, want %v", g.ScanID, g.Highlighted, want)
			}
		}
	})

	t.Run("empty target highlights nothing", func(t *testing.T) {
		v := timelineFullView(scans, "")
		for _, g := range v.Groups {
			if g.Highlighted {
				t.Errorf("group %s highlighted with empty target", g.ScanID)
			}
		}
	})
}
