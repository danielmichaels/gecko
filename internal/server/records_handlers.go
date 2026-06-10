package server

import (
	"context"
	"errors"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/service"
)

type RecordHistoryOutput struct {
	Body struct {
		DomainName string              `json:"domain_name"`
		History    []dto.RecordHistory `json:"history"`
	}
}

type RecordHistoryInput struct {
	DomainID string `path:"id"     example:"domain_00000001" doc:"Domain UID"`
	QType    string `query:"qtype" example:"a,cname"         doc:"Comma-separated record types to filter. Omit for all."`
}

func (app *Server) handleRecordsHistory(
	ctx context.Context,
	i *RecordHistoryInput,
) (*RecordHistoryOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	result, err := app.Svc.RecordsService().History(ctx, p, i.DomainID, i.QType)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return nil, huma.Error404NotFound("domain not found")
		}
		if errors.Is(err, service.ErrInvalidInput) {
			badType := strings.TrimPrefix(err.Error(), service.ErrInvalidInput.Error()+": ")
			return nil, huma.Error400BadRequest("invalid record type: " + badType)
		}
		return nil, huma.Error500InternalServerError("failed to load record history", err)
	}
	resp := &RecordHistoryOutput{}
	resp.Body.DomainName = result.DomainName
	resp.Body.History = result.History
	return resp, nil
}

// /records?qtype=a,aaaa,cname             // List all records with optional type filtering
// /records/:domainID?qtype=a,aaaa         // Get records for specific domain with optional type filtering
// /records DELETE                         // Delete records (no create/update by users)
// /records/:domainID/history?qtype=a,cname // Get history for domain's records

type RecordsListOutput struct {
	Body struct {
		Count   int64          `json:"count"`
		Records dto.AllRecords `json:"records"`
	}
}

// handleRecordsList handles the retrieval of DNS records for a domain. The service
// returns every record for the domain in one query (DNS record sets are bounded), so
// the response carries a simple total Count rather than a paginated surface.
func (app *Server) handleRecordsList(ctx context.Context, i *struct {
	DomainID string `path:"id" example:"domain_00000001" doc:"Domain UID"`
	QType    string `query:"qtype" example:"a,aaaa,cname,mx,txt,ns,doa,ptr,caa,srv,dnskey,ds,rrsig" doc:"Comma-separated list of record types to fetch. Not providing a qtype returns all record types."`
},
) (*RecordsListOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}

	recordTypes := service.ParseRecordTypes(i.QType)

	result, err := app.Svc.RecordsService().List(ctx, p, i.DomainID, recordTypes)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return nil, huma.Error404NotFound("domain not found")
		}
		if errors.Is(err, service.ErrInvalidInput) {
			badType := strings.TrimPrefix(err.Error(), service.ErrInvalidInput.Error()+": ")
			return nil, huma.Error400BadRequest("invalid record type: " + badType)
		}
		return nil, huma.Error500InternalServerError("failed to list records", err)
	}

	resp := &RecordsListOutput{}
	resp.Body.Count = result.TotalRecords
	resp.Body.Records = result.Records
	return resp, nil
}
