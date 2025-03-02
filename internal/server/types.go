package server

// PaginationQuery represents the query parameters for paginating a list of domains.
// PageSize specifies the number of domains to return per page, with a default of 20.
// PageNumber specifies the page offset for pagination, with a default of 1.
type PaginationQuery struct {
	PageSize   int32 `query:"page_size" example:"20" default:"20" doc:"Number of domains to return. Optional."`
	PageNumber int32 `query:"page" example:"1" default:"1" doc:"Offset for pagination. Optional."`
	Offset     int32 `query:"offset" example:"0" default:"0" doc:"Offset for pagination. Optional."`
}

// GetPageSize returns the page size with default handling
func (p *PaginationQuery) GetPageSize() int32 {
	if p.PageSize <= 0 {
		return 25 // Default page size
	}
	return p.PageSize
}

// GetPageNumber returns the page number with default handling
func (p *PaginationQuery) GetPageNumber() int32 {
	if p.PageNumber <= 0 {
		return 1 // Default to first page
	}
	return p.PageNumber
}

// GetOffset calculates the SQL offset from page number and size
func (p *PaginationQuery) GetOffset() int32 {
	return (p.GetPageNumber() - 1) * p.GetPageSize()
}

// GetPaginationParams returns all pagination parameters in a standardized way
func (p *PaginationQuery) GetPaginationParams() (pageSize, pageNumber, offset int32) {
	pageSize = p.GetPageSize()
	pageNumber = p.GetPageNumber()
	offset = p.GetOffset()
	return
}

type PaginationMetadata struct {
	Total      int64 `json:"total_results" example:"100" doc:"Total number of items found."`
	Page       int32 `json:"page"  example:"1" doc:"Page of number for items returned."`
	PageSize   int32 `json:"page_size"   example:"10" doc:"Number of items per page."`
	TotalPages int32 `json:"total_pages"    example:"1" doc:"Total number of pages."`
	Count      int32 `json:"count"   example:"14" doc:"Item count for the current page."`
}

func NewPaginationMetadata(
	totalCount int64,
	pageSize, pageNumber, currentPageCount int32,
) PaginationMetadata {
	totalPages := int32(1)
	if totalCount > 0 {
		totalPages = int32((totalCount + int64(pageSize) - 1) / int64(pageSize))
	}

	return PaginationMetadata{
		Total:      totalCount,
		PageSize:   pageSize,
		Page:       pageNumber,
		TotalPages: totalPages,
		Count:      currentPageCount,
	}
}
