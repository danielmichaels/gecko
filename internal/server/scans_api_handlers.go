package server

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/service"
)

// ScanChangeItem is one entity-type rollup within a scan's diff.
type ScanChangeItem struct {
	EntityType string `json:"entity_type"`
	ChangeType string `json:"change_type"`
	Count      int    `json:"count"`
}

// ScanItem is one scan run in the flat tenant feed.
type ScanItem struct {
	StartedAt     time.Time        `json:"started_at"`
	ScanUID       string           `json:"scan_uid"`
	DomainUID     string           `json:"domain_uid"`
	DomainName    string           `json:"domain_name"`
	Source        string           `json:"source"`
	ParentScanUID string           `json:"parent_scan_uid,omitempty"`
	State         string           `json:"state"`
	Changes       []ScanChangeItem `json:"changes,omitempty"`
	CreatedCount  int              `json:"created_count"`
	UpdatedCount  int              `json:"updated_count"`
	DeletedCount  int              `json:"deleted_count"`
	TotalChanges  int              `json:"total_changes"`
	IsBaseline    bool             `json:"is_baseline"`
}

func toScanItem(v service.FlatScanView) ScanItem {
	changes := make([]ScanChangeItem, 0, len(v.Changes))
	for _, c := range v.Changes {
		changes = append(changes, ScanChangeItem{
			EntityType: c.EntityType,
			ChangeType: c.ChangeType,
			Count:      c.Count,
		})
	}
	return ScanItem{
		ScanUID:       v.ScanUID,
		DomainUID:     v.DomainUID,
		DomainName:    v.DomainName,
		Source:        v.Source,
		ParentScanUID: v.ParentScanUID,
		State:         v.State,
		StartedAt:     v.StartedAt,
		IsBaseline:    v.IsBaseline,
		CreatedCount:  v.CreatedCount,
		UpdatedCount:  v.UpdatedCount,
		DeletedCount:  v.DeletedCount,
		TotalChanges:  v.TotalChanges,
		Changes:       changes,
	}
}

type ScansListInput struct {
	Source      string `query:"source"       example:"user_supplied" doc:"Filter by source: user_supplied|discovered. Optional." enum:"user_supplied,discovered,"`
	DomainQuery string `query:"q"            example:"acme"          doc:"Case-insensitive domain-name substring. Optional."`
	WindowDays  int    `query:"window_days"  example:"7" default:"7" doc:"Days of history to return. 0 means all-time."`
	ChangedOnly bool   `query:"changed_only" example:"false"         doc:"Hide clean (no-change) re-scans; baselines are always kept. Optional."`
	PaginationQuery
}

type ScansListOutput struct {
	Body struct {
		Pagination *PaginationMetadata `json:"pagination"`
		Scans      []ScanItem          `json:"scans"`
	}
}

// handleScansList serves the tenant-wide, flat, paginated scan feed. The window
// defaults to 7 days (window_days=0 requests all-time) so the feed is never an
// unbounded scan of the observation history.
func (app *Server) handleScansList(
	ctx context.Context,
	i *ScansListInput,
) (*ScansListOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}

	pageSize, pageNumber, offset := i.GetPaginationParams()
	result, err := app.Svc.ScansService().ListByTenantFlat(ctx, p, service.ScansListOptions{
		Source:      i.Source,
		DomainQuery: i.DomainQuery,
		WindowDays:  i.WindowDays,
		ChangedOnly: i.ChangedOnly,
	}, pageSize, offset)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to list scans", err)
	}

	items := make([]ScanItem, 0, len(result.Scans))
	for _, v := range result.Scans {
		items = append(items, toScanItem(v))
	}
	pagination := NewPaginationMetadata(result.TotalCount, pageSize, pageNumber, int32(len(items)))

	resp := &ScansListOutput{}
	resp.Body.Pagination = &pagination
	resp.Body.Scans = items
	return resp, nil
}
