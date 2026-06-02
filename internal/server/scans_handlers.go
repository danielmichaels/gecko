package server

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/store"
)

type DomainTimelineOutput struct {
	Body struct {
		DomainName string         `json:"domain_name"`
		Scans      []dto.ScanDiff `json:"scans"`
	}
}

// handleDomainTimeline returns a domain's scan-by-scan change timeline: every
// scan that recorded a change (newest first) with the observations from it,
// grouped by scan uid. Keyed on (tenant_id, domain_name) so it survives a domain
// delete/re-add, and carries parent_scan_uid lineage so child (discovered) scans
// can be nested under the apex scan that found them. A single join query supplies
// both the changes and their scan metadata; scans with no observations never
// appear, so the timeline reads as a pure change history.
func (app *Server) handleDomainTimeline(
	ctx context.Context,
	i *DomainGetInput,
) (*DomainTimelineOutput, error) {
	domain, err := app.Db.DomainsGetByID(ctx, i.ID)
	if err != nil {
		return nil, huma.Error404NotFound("domain not found")
	}

	rows, err := app.Db.ObservationsListTimelineByTenantDomainName(
		ctx,
		store.ObservationsListTimelineByTenantDomainNameParams{
			TenantID:   domain.TenantID.Int32,
			DomainName: domain.Name,
		},
	)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to load timeline", err)
	}

	resp := &DomainTimelineOutput{}
	resp.Body.DomainName = domain.Name
	resp.Body.Scans = []dto.ScanDiff{}

	// Rows arrive ordered newest-scan-first, then by observation id, so grouping
	// by first-seen scan uid preserves both scan order and change order.
	byUID := map[string]int{}
	for _, row := range rows {
		idx, seen := byUID[row.ScanUid]
		if !seen {
			sd := dto.ScanDiff{
				ScanUID: row.ScanUid,
				Source:  string(row.ScanSource),
				Changes: []dto.RecordHistory{},
			}
			if row.ScanStartedAt.Valid {
				sd.StartedAt = row.ScanStartedAt.Time.Format(time.RFC3339)
			}
			if row.ParentScanUid.Valid {
				sd.ParentScanUID = row.ParentScanUid.String
			}
			resp.Body.Scans = append(resp.Body.Scans, sd)
			idx = len(resp.Body.Scans) - 1
			byUID[row.ScanUid] = idx
		}
		resp.Body.Scans[idx].Changes = append(
			resp.Body.Scans[idx].Changes, dto.TimelineRowToRecordHistory(row),
		)
	}
	return resp, nil
}
