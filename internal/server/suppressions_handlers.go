package server

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
)

// SuppressionItem is one silence rule or ack in an API response.
type SuppressionItem struct {
	UID        string `json:"uid"`
	Scope      string `json:"scope"` // tenant | domain | finding
	State      string `json:"state"`
	Kind       string `json:"kind,omitempty"`
	IssueType  string `json:"issue_type,omitempty"`
	FindingUID string `json:"finding_uid,omitempty"`
	DomainUID  string `json:"domain_uid,omitempty"`
	DomainName string `json:"domain_name,omitempty"`
	Reason     string `json:"reason,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

func toSuppressionItem(v service.SuppressionView) SuppressionItem {
	return SuppressionItem{
		UID:        v.UID,
		Scope:      v.Scope,
		State:      v.State,
		Kind:       v.Kind,
		IssueType:  v.IssueType,
		FindingUID: v.FindingUID,
		DomainUID:  v.DomainUID,
		DomainName: v.DomainName,
		Reason:     v.Reason,
		CreatedBy:  v.CreatedBy,
		CreatedAt:  v.CreatedAt,
		ExpiresAt:  v.ExpiresAt,
	}
}

type SuppressionsListOutput struct {
	Body struct {
		Suppressions []SuppressionItem `json:"suppressions"`
	}
}

// handleSuppressionsList returns every silence rule and ack for the tenant.
func (app *Server) handleSuppressionsList(
	ctx context.Context,
	_ *struct{},
) (*SuppressionsListOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	views, err := app.Svc.SuppressionsService().ListSuppressions(ctx, p)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to list suppressions", err)
	}
	resp := &SuppressionsListOutput{}
	resp.Body.Suppressions = make([]SuppressionItem, 0, len(views))
	for _, v := range views {
		resp.Body.Suppressions = append(resp.Body.Suppressions, toSuppressionItem(v))
	}
	return resp, nil
}

type SuppressionRuleCreateInput struct {
	Body struct {
		Kind      string  `json:"kind"       example:"NS_CONFIG" doc:"Finding kind to silence."`
		IssueType string  `json:"issue_type" example:"insufficient_nameservers" doc:"Check code to silence."`
		DomainUID *string `json:"domain_uid,omitempty" example:"domain_00000001" doc:"Scope to one domain. Omit for tenant-global."`
		Reason    string  `json:"reason,omitempty" doc:"Optional note."`
		ExpiresAt *string `json:"expires_at,omitempty" doc:"Optional RFC3339 expiry (snooze). Omit for permanent."`
	}
}

type SuppressionOutput struct {
	Body SuppressionItem
}

// handleSuppressionRuleCreate creates (or refreshes) a silence rule. Owner/manager only.
func (app *Server) handleSuppressionRuleCreate(
	ctx context.Context,
	i *SuppressionRuleCreateInput,
) (*SuppressionOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	expires, err := parseOptExpiry(i.Body.ExpiresAt)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid expires_at: " + err.Error())
	}
	row, err := app.Svc.SuppressionsService().CreateSilenceRule(
		ctx, p, i.Body.Kind, i.Body.IssueType, i.Body.DomainUID, i.Body.Reason, expires,
	)
	if err != nil {
		return nil, suppressionErr(err, "failed to create silence rule")
	}
	return &SuppressionOutput{Body: toSuppressionItem(suppressionRowView(row))}, nil
}

type SuppressionDeleteInput struct {
	UID string `json:"uid" path:"uid" example:"fsup_00000001"`
}

type SuppressionDeleteOutput struct {
	Body struct {
		Deleted bool `json:"deleted"`
	}
}

// handleSuppressionDelete removes a rule or ack by uid. Owner/manager only.
func (app *Server) handleSuppressionDelete(
	ctx context.Context,
	i *SuppressionDeleteInput,
) (*SuppressionDeleteOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	if err := app.Svc.SuppressionsService().DeleteSuppression(ctx, p, i.UID); err != nil {
		return nil, suppressionErr(err, "failed to delete suppression")
	}
	resp := &SuppressionDeleteOutput{}
	resp.Body.Deleted = true
	return resp, nil
}

type FindingAcknowledgeInput struct {
	FindingUID string `json:"finding_uid" path:"finding_uid" example:"spf_00000001"`
	Body       struct {
		State     string  `json:"state" example:"acknowledged" enum:"acknowledged,resolved" doc:"acknowledged or resolved."`
		Reason    string  `json:"reason,omitempty"`
		ExpiresAt *string `json:"expires_at,omitempty" doc:"Optional RFC3339 expiry."`
	}
}

// handleFindingAcknowledge acks/resolves a single finding by uid. Owner/manager only.
func (app *Server) handleFindingAcknowledge(
	ctx context.Context,
	i *FindingAcknowledgeInput,
) (*SuppressionOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	expires, err := parseOptExpiry(i.Body.ExpiresAt)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid expires_at: " + err.Error())
	}
	row, err := app.Svc.SuppressionsService().AcknowledgeFinding(
		ctx, p, i.FindingUID, store.SuppressionState(i.Body.State), i.Body.Reason, expires,
	)
	if err != nil {
		return nil, suppressionErr(err, "failed to acknowledge finding")
	}
	return &SuppressionOutput{Body: toSuppressionItem(suppressionRowView(row))}, nil
}

type FindingUnacknowledgeInput struct {
	FindingUID string `json:"finding_uid" path:"finding_uid" example:"spf_00000001"`
}

// handleFindingUnacknowledge removes a finding's ack. Owner/manager only.
func (app *Server) handleFindingUnacknowledge(
	ctx context.Context,
	i *FindingUnacknowledgeInput,
) (*SuppressionDeleteOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	if err := app.Svc.SuppressionsService().UnacknowledgeFinding(ctx, p, i.FindingUID); err != nil {
		return nil, suppressionErr(err, "failed to un-acknowledge finding")
	}
	resp := &SuppressionDeleteOutput{}
	resp.Body.Deleted = true
	return resp, nil
}

// suppressionErr maps service sentinels to Huma HTTP errors.
func suppressionErr(err error, fallback string) error {
	switch {
	case errors.Is(err, service.ErrForbidden):
		return huma.Error403Forbidden(err.Error())
	case errors.Is(err, service.ErrNotFound):
		return huma.Error404NotFound("not found")
	case errors.Is(err, service.ErrInvalidInput):
		return huma.Error400BadRequest(err.Error())
	default:
		return huma.Error500InternalServerError(fallback, err)
	}
}

func parseOptExpiry(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// suppressionRowView adapts a stored row to the presentation view used by the API
// responses, mirroring SuppressionsService.ListSuppressions' field mapping.
func suppressionRowView(row store.FindingSuppressions) service.SuppressionView {
	scope := "tenant"
	switch {
	case row.FindingUid.Valid:
		scope = "finding"
	case row.DomainID.Valid:
		scope = "domain"
	}
	return service.SuppressionView{
		UID:        row.Uid,
		Scope:      scope,
		State:      string(row.State),
		Kind:       row.Kind.String,
		IssueType:  row.IssueType.String,
		FindingUID: row.FindingUid.String,
		Reason:     row.Reason.String,
	}
}
