package server

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

type DomainTimelineOutput struct {
	Body struct {
		DomainName string         `json:"domain_name"`
		Scans      []dto.ScanDiff `json:"scans"`
	}
}

// handleDomainTimeline returns a domain's scan-by-scan change timeline: every
// scan (newest first) with the observations recorded during it, grouped by
// scan_id. Keyed on (tenant_id, domain_name) so it survives a domain delete/
// re-add, and carries parent_scan_id lineage so child (discovered) scans can be
// nested under the apex scan that found them.
func (app *Server) handleDomainTimeline(
	ctx context.Context,
	i *DomainGetInput,
) (*DomainTimelineOutput, error) {
	domain, err := app.Db.DomainsGetByID(ctx, i.ID)
	if err != nil {
		return nil, huma.Error404NotFound("domain not found")
	}

	scans, err := app.Db.ScansListByTenantDomainName(ctx, store.ScansListByTenantDomainNameParams{
		TenantID:   domain.TenantID.Int32,
		DomainName: domain.Name,
	})
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to load scans", err)
	}

	resp := &DomainTimelineOutput{}
	resp.Body.DomainName = domain.Name
	resp.Body.Scans = []dto.ScanDiff{}
	for _, s := range scans {
		obs, err := app.Db.ObservationsListByScan(ctx, pgtype.Int8{Int64: s.ID, Valid: true})
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to load scan observations", err)
		}
		changes := make([]dto.RecordHistory, 0, len(obs))
		for _, o := range obs {
			changes = append(changes, dto.ObservationToRecordHistory(o))
		}
		resp.Body.Scans = append(resp.Body.Scans, dto.ScanToScanDiff(s, changes))
	}
	return resp, nil
}
