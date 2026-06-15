package server

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/service"
)

// FindingItem is one security finding in an API response. The tenant-wide list
// populates every field; the per-domain list leaves the domain-identity fields
// (FindingUID, DomainUID, DomainName, FirstSeen) empty because the domain is
// implied by the URL and the per-domain service path does not carry them.
type FindingItem struct {
	FindingUID  string `json:"finding_uid,omitempty"`
	DomainUID   string `json:"domain_uid,omitempty"`
	DomainName  string `json:"domain_name,omitempty"`
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Tier        string `json:"tier"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	FixHint     string `json:"fix_hint"`
	FirstSeen   string `json:"first_seen,omitempty"`
}

func toFindingItem(f service.FindingView) FindingItem {
	return FindingItem{
		FindingUID:  f.FindingUID,
		DomainUID:   f.DomainUID,
		DomainName:  f.DomainName,
		Kind:        f.Kind,
		Severity:    f.Severity,
		Tier:        f.Tier,
		Title:       f.Title,
		Description: f.Description,
		Evidence:    f.Evidence,
		FixHint:     f.FixHint,
		FirstSeen:   f.FirstSeen,
	}
}

type FindingsListInput struct {
	Severity         string `query:"severity"          example:"crit"  doc:"Filter by tier: crit|high|med|low. Optional." enum:"crit,high,med,low,"`
	Kind             string `query:"kind"              example:"SPF"   doc:"Filter by type: SPF|DKIM|DMARC|ZONE|CERT|DNSSEC|CAA_CONFIG|CAA_COMPLIANCE|MIN_RECORDS|EMAIL_COMPLIANCE|NS_CONFIG|NS_REDUNDANCY. Optional." enum:"SPF,DKIM,DMARC,ZONE,CERT,DNSSEC,CAA_CONFIG,CAA_COMPLIANCE,MIN_RECORDS,EMAIL_COMPLIANCE,NS_CONFIG,NS_REDUNDANCY,"`
	DomainQuery      string `query:"q"                 example:"acme"  doc:"Case-insensitive domain-name substring. Optional."`
	IncludeCompliant bool   `query:"include_compliant" example:"false" doc:"Include compliant/closed findings. Optional."`
	PaginationQuery
}

type FindingsListOutput struct {
	Body struct {
		Pagination *PaginationMetadata `json:"pagination"`
		Findings   []FindingItem       `json:"findings"`
	}
}

// handleFindingsList serves the tenant-wide, flat, paginated findings feed.
func (app *Server) handleFindingsList(
	ctx context.Context,
	i *FindingsListInput,
) (*FindingsListOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}

	pageSize, pageNumber, offset := i.GetPaginationParams()
	result, err := app.Svc.FindingsService().ListByTenantFlat(ctx, p, service.FindingsListOptions{
		Severity:         i.Severity,
		Kind:             i.Kind,
		DomainQuery:      i.DomainQuery,
		IncludeCompliant: i.IncludeCompliant,
	}, pageSize, offset)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to list findings", err)
	}

	items := make([]FindingItem, 0, len(result.Findings))
	for _, f := range result.Findings {
		items = append(items, toFindingItem(f))
	}
	pagination := NewPaginationMetadata(result.TotalCount, pageSize, pageNumber, int32(len(items)))

	resp := &FindingsListOutput{}
	resp.Body.Pagination = &pagination
	resp.Body.Findings = items
	return resp, nil
}

type DomainFindingsOutput struct {
	Body struct {
		Summary  FindingsSummary `json:"summary"`
		Findings []FindingItem   `json:"findings"`
	}
}

// FindingsSummary is the per-domain count strip (info/compliant collapse into healthy).
type FindingsSummary struct {
	TotalCount    int `json:"total_count"`
	CriticalCount int `json:"critical_count"`
	WarningCount  int `json:"warning_count"`
	HealthyCount  int `json:"healthy_count"`
}

// handleDomainFindings serves a single domain's findings. Tenant isolation is
// enforced inside ListByDomain, which gates on the domain belonging to the caller's
// tenant and returns ErrNotFound otherwise.
func (app *Server) handleDomainFindings(
	ctx context.Context,
	i *DomainGetInput,
) (*DomainFindingsOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}

	result, err := app.Svc.FindingsService().ListByDomain(ctx, p, i.ID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return nil, huma.Error404NotFound("domain not found")
		}
		return nil, huma.Error500InternalServerError("failed to list findings", err)
	}

	items := make([]FindingItem, 0, len(result.Findings))
	for _, f := range result.Findings {
		items = append(items, toFindingItem(f))
	}

	resp := &DomainFindingsOutput{}
	resp.Body.Summary = FindingsSummary{
		TotalCount:    result.TotalCount,
		CriticalCount: result.CriticalCount,
		WarningCount:  result.WarningCount,
		HealthyCount:  result.HealthyCount,
	}
	resp.Body.Findings = items
	return resp, nil
}
