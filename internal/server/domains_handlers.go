package server

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
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
	FilterName string `query:"name" example:"example.com" doc:"Filter by domain name. Optional."`
	PaginationQuery
},
) (*DomainListOutput, error) {
	tenantID := pgtype.Int4{Int32: 1, Valid: true} // fixme: Replace with actual tenant ID
	pageSize, pageNumber, offset := i.PaginationQuery.GetPaginationParams()
	var result domainsSearchQueryResult
	var err error
	if i.FilterName != "" {
		result, err = app.executeSearchQuery(ctx, tenantID, i.FilterName, pageSize, offset)
	} else {
		result, err = app.executeListQuery(ctx, tenantID, pageSize, offset)
	}

	if err != nil {
		return nil, err
	}

	paginationMetadata := NewPaginationMetadata(
		result.TotalCount,
		pageSize,
		pageNumber,
		int32(len(result.Domains)),
	)
	resp := &DomainListOutput{
		Body: struct {
			Pagination *PaginationMetadata `json:"pagination"`
			Domains    []dto.Domain        `json:"domains"`
		}{
			Domains:    dto.DomainsToAPI(result.Domains),
			Pagination: &paginationMetadata,
		},
	}
	return resp, nil
}

type domainsSearchQueryResult struct {
	Domains    []store.Domains
	TotalCount int64
}

func (app *Server) executeSearchQuery(
	ctx context.Context,
	tenantID pgtype.Int4,
	filter string,
	limit, offset int32,
) (domainsSearchQueryResult, error) {
	rows, err := app.Db.DomainsSearchByName(ctx, store.DomainsSearchByNameParams{
		TenantID: tenantID,
		Name:     "%" + filter + "%",
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		return domainsSearchQueryResult{}, err
	}

	var totalCount int64
	if len(rows) > 0 {
		totalCount = rows[0].TotalCount
	}

	return domainsSearchQueryResult{
		Domains:    dto.DomainSearchByNameRowToDomains(rows),
		TotalCount: totalCount,
	}, nil
}

// Helper function for list query
func (app *Server) executeListQuery(
	ctx context.Context,
	tenantID pgtype.Int4,
	limit, offset int32,
) (domainsSearchQueryResult, error) {
	rows, err := app.Db.DomainsListByTenantID(ctx, store.DomainsListByTenantIDParams{
		TenantID: tenantID,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		return domainsSearchQueryResult{}, err
	}

	var totalCount int64
	if len(rows) > 0 {
		totalCount = rows[0].TotalCount
	}

	return domainsSearchQueryResult{
		Domains:    dto.DomainsListByTenantIDToDomains(rows),
		TotalCount: totalCount,
	}, nil
}

type DomainGetInput struct {
	ID string `json:"id" example:"domain_00000001" path:"id"`
}

func (app *Server) handleDomainGet(ctx context.Context, i *DomainGetInput) (*DomainOutput, error) {
	domain, err := app.Db.DomainsGetByID(ctx, i.ID)
	if err != nil {
		return nil, huma.Error404NotFound("domain not found")
	}

	resp := &DomainOutput{Body: dto.DomainToAPI(domain)}
	return resp, nil
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
	patchDomain, err := app.Db.DomainsGetByID(ctx, i.ID)
	if err != nil {
		app.Log.Error("failed to get domain", "error", err)
		return nil, huma.Error404NotFound("domain not found")
	}
	status := patchDomain.Status
	if i.Body.Status != "" {
		status = store.DomainStatus(i.Body.Status)
	}
	domainSource := patchDomain.Source
	if i.Body.Source != "" {
		domainSource = store.DomainSource(i.Body.Source)
	}
	domainType := patchDomain.DomainType
	if i.Body.DomainType != "" {
		domainType = store.DomainType(i.Body.DomainType)
	}
	params := store.DomainsUpdateByIDParams{
		Uid:        i.ID,
		Status:     status,
		DomainType: domainType,
		Source:     domainSource,
	}
	domain, err := app.Db.DomainsUpdateByID(ctx, params)
	if err != nil {
		app.Log.Error("failed to update domain", "error", err)
		return nil, huma.Error500InternalServerError("failed to create domain", err)
	}
	domainObj := store.Domains{
		ID:         domain.ID,
		Uid:        domain.Uid,
		TenantID:   pgtype.Int4{Int32: 1, Valid: true},
		Name:       domain.Name,
		DomainType: domain.DomainType,
		Source:     domain.Source,
		Status:     domain.Status,
		CreatedAt:  domain.CreatedAt,
		UpdatedAt:  domain.UpdatedAt,
	}
	if err := app.scheduleDomainJobs(ctx, domainObj); err != nil {
		return nil, huma.Error500InternalServerError("failed to commit transaction", err)
	}
	return &DomainOutput{Body: dto.DomainToAPI(domainObj)}, nil
}

type DomainDeleteInput struct {
	ID string `json:"id" path:"id" example:"domain_00000001"`
}

func (app *Server) handleDomainDelete(
	ctx context.Context,
	i *DomainDeleteInput,
) (*struct{}, error) {
	_, err := app.Db.DomainsDeleteByID(ctx, i.ID)
	if err != nil {
		app.Log.Error("failed to delete domain", "error", err, "id", i.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, huma.Error404NotFound("domain not found")
		}
		return nil, huma.Error500InternalServerError("failed to delete domain")
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
	_, err := app.Db.DomainsGetByName(ctx, store.DomainsGetByNameParams{
		TenantID: pgtype.Int4{Int32: 1, Valid: true}, // todo: get from context
		Name:     i.Body.Domain,
	})
	if err == nil {
		return nil, huma.Error409Conflict("domain already exists")
	}
	status := store.DomainStatusActive
	if i.Body.Status != "" {
		status = store.DomainStatus(i.Body.Status)
	}
	domainSource := store.DomainSourceUserSupplied
	if i.Body.Source != "" {
		domainSource = store.DomainSource(i.Body.Source)
	}
	domainType := store.DomainTypeSubdomain
	if i.Body.DomainType != "" {
		domainType = store.DomainType(i.Body.DomainType)
	}
	domain, err := app.Db.DomainsCreate(ctx, store.DomainsCreateParams{
		Name:       i.Body.Domain,
		TenantID:   pgtype.Int4{Int32: int32(1), Valid: true}, // todo: get from context
		DomainType: domainType,
		Source:     domainSource,
		Status:     status,
	})
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to create domain", err)
	}
	domainObj := store.Domains{
		ID:         domain.ID,
		Uid:        domain.Uid,
		TenantID:   pgtype.Int4{Int32: 1, Valid: true},
		Name:       domain.Name,
		DomainType: domain.DomainType,
		Source:     domain.Source,
		Status:     domain.Status,
		CreatedAt:  domain.CreatedAt,
		UpdatedAt:  domain.UpdatedAt,
	}
	if err := app.scheduleDomainJobs(ctx, domainObj); err != nil {
		return nil, huma.Error500InternalServerError("failed to commit transaction", err)
	}
	return &DomainOutput{Body: dto.DomainToAPI(domainObj)}, nil
}
