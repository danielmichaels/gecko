package server

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/service"
)

type DomainInput struct {
	Body struct {
		Domain string `json:"domain" example:"domain_00000001" doc:"Name of the domain."`
	}
}
type DomainOutput struct {
	Body dto.Domain
}
type DomainListOutput struct {
	Body struct {
		Pagination *PaginationMetadata `json:"pagination"`
		Domains    []dto.Domain        `json:"domains"`
	}
}
type DomainBody struct {
	Domain     string `json:"domain" example:"example.com" doc:"Name of the domain."`
	UID        string `json:"uid" example:"domain_00000001" doc:"Unique identifier for the domain."`
	DomainType string `json:"domain_type" example:"tld" doc:"Type of the domain."`
	Source     string `json:"source" example:"user_supplied" doc:"Source of the domain."`
	Status     string `json:"status" example:"active" doc:"Status of the domain."`
	CreatedAt  string `json:"created_at" example:"2021-01-01T00:00:00Z" doc:"Creation date of the domain."`
	UpdatedAt  string `json:"updated_at" example:"2021-01-01T00:00:00Z" doc:"Last update date of the domain."`
}

func (app *Server) handleDomainList(ctx context.Context, i *struct {
	FilterName string `query:"name"        example:"example.com"  doc:"Filter by domain name. Optional."`
	Source     string `query:"source"      enum:"user_supplied,discovered"             example:"user_supplied" doc:"Filter by provenance: user_supplied (explicitly added) or discovered (found by enumeration). Optional."`
	DomainType string `query:"domain_type" enum:"tld,subdomain,wildcard,old,other"     example:"tld"           doc:"Filter by domain structure. Optional."`
	PaginationQuery
},
) (*DomainListOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	pageSize, pageNumber, offset := i.GetPaginationParams()
	result, err := app.Svc.DomainsService().List(ctx, p, service.DomainsListParams{
		FilterName: i.FilterName,
		Source:     i.Source,
		DomainType: i.DomainType,
		PageSize:   pageSize,
		Offset:     offset,
	})
	if err != nil {
		if errors.Is(err, service.ErrInvalidInput) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		return nil, huma.Error500InternalServerError("failed to list domains", err)
	}

	paginationMetadata := NewPaginationMetadata(
		result.TotalCount,
		pageSize,
		pageNumber,
		int32(len(result.Domains)),
	)
	return &DomainListOutput{
		Body: struct {
			Pagination *PaginationMetadata `json:"pagination"`
			Domains    []dto.Domain        `json:"domains"`
		}{
			Domains:    dto.DomainsToAPI(result.Domains),
			Pagination: &paginationMetadata,
		},
	}, nil
}

type DomainGetInput struct {
	ID string `json:"id" example:"domain_00000001" path:"id"`
}

func (app *Server) handleDomainGet(ctx context.Context, i *DomainGetInput) (*DomainOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	domain, err := app.Svc.DomainsService().Get(ctx, p, i.ID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return nil, huma.Error404NotFound("domain not found")
		}
		return nil, huma.Error500InternalServerError("failed to get domain", err)
	}
	return &DomainOutput{Body: dto.DomainToAPI(domain)}, nil
}

type DomainUpdateInput struct {
	ID   string `json:"id" path:"id" example:"domain_00000001"`
	Body struct {
		DomainType string `json:"domain_type" required:"false" example:"tld" doc:"Domain category such as TLD, subdomain, or wildcard."`
		Source     string `json:"source" required:"false" example:"user_supplied" doc:"Source of the domain."`
		Status     string `json:"status" required:"false" example:"active" doc:"Status of the domain."`
	}
}

func (app *Server) handleDomainUpdate(
	ctx context.Context,
	i *DomainUpdateInput,
) (*DomainOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	domain, err := app.Svc.DomainsService().Update(ctx, p, i.ID, service.DomainsUpdateParams{
		DomainType: i.Body.DomainType,
		Source:     i.Body.Source,
		Status:     i.Body.Status,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrNotFound):
			return nil, huma.Error404NotFound("domain not found")
		default:
			return nil, huma.Error500InternalServerError("failed to update domain", err)
		}
	}
	return &DomainOutput{Body: dto.DomainToAPI(domain)}, nil
}

// DomainDeletionImpactInput defines the input for the domain deletion impact endpoint
type DomainDeletionImpactInput struct {
	ID string `json:"id" path:"id" example:"domain_00000001"`
}

// DomainDeletionImpactOutput defines the output structure for domain deletion impact
type DomainDeletionImpactOutput struct {
	Body struct {
		Count int64 `json:"count" example:"42" doc:"Number of domains that would be deleted"`
	}
}

// handleDomainDeletionImpact returns an estimate of how many domains would be deleted
func (app *Server) handleDomainDeletionImpact(
	ctx context.Context,
	i *DomainDeletionImpactInput,
) (*DomainDeletionImpactOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	count, err := app.Svc.DomainsService().DeletionImpact(ctx, p, i.ID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return nil, huma.Error404NotFound("domain not found")
		}
		return nil, huma.Error500InternalServerError("failed to count domains for deletion")
	}
	resp := &DomainDeletionImpactOutput{}
	resp.Body.Count = count
	return resp, nil
}

type DomainDeleteInput struct {
	ID string `json:"id" path:"id" example:"domain_00000001"`
}

func (app *Server) handleDomainDelete(
	ctx context.Context,
	i *DomainDeleteInput,
) (*struct{}, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	if err := app.Svc.DomainsService().Delete(ctx, p, i.ID); err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrNotFound):
			return nil, huma.Error404NotFound("domain not found")
		default:
			return nil, huma.Error500InternalServerError("failed to delete domain")
		}
	}
	return nil, nil
}

type DomainCreateInput struct {
	Body struct {
		Domain     string `json:"domain" required:"true" format:"hostname" example:"example.com" doc:"Name of the domain."`
		DomainType string `json:"domain_type" required:"false" example:"tld" doc:"Domain category such as TLD, subdomain, or wildcard."`
		Source     string `json:"source" required:"false" example:"user_supplied" doc:"Source of the domain."`
		Status     string `json:"status" required:"false" example:"active" doc:"Status of the domain."`
	}
}

func (app *Server) handleDomainCreate(
	ctx context.Context,
	i *DomainCreateInput,
) (*DomainOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	domain, err := app.Svc.DomainsService().Create(ctx, p, service.DomainsCreateParams{
		Domain:     i.Body.Domain,
		DomainType: i.Body.DomainType,
		Source:     i.Body.Source,
		Status:     i.Body.Status,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrConflict):
			return nil, huma.Error409Conflict("domain already exists")
		default:
			return nil, huma.Error500InternalServerError("failed to create domain", err)
		}
	}
	return &DomainOutput{Body: dto.DomainToAPI(domain)}, nil
}
