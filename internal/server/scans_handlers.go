package server

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/service"
)

type DomainTimelineOutput struct {
	Body struct {
		DomainName string         `json:"domain_name"`
		Scans      []dto.ScanDiff `json:"scans"`
	}
}

func (app *Server) handleDomainTimeline(
	ctx context.Context,
	i *DomainGetInput,
) (*DomainTimelineOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	result, err := app.Svc.RecordsService().Timeline(ctx, p, i.ID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return nil, huma.Error404NotFound("domain not found")
		}
		return nil, huma.Error500InternalServerError("failed to load timeline", err)
	}
	resp := &DomainTimelineOutput{}
	resp.Body.DomainName = result.DomainName
	resp.Body.Scans = result.Scans
	return resp, nil
}
