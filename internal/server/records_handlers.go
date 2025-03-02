package server

import (
	"context"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/jackc/pgx/v5/pgtype"
)

// /records?qtype=a,aaaa,cname             // List all records with optional type filtering
// /records/:domainID?qtype=a,aaaa         // Get records for specific domain with optional type filtering
// /records DELETE                         // Delete records (no create/update by users)
// /records/:domainID/history?qtype=a,cname // Get history for domain's records

type RecordsListOutput struct {
	Body struct {
		Pagination *PaginationMetadata `json:"pagination"`
		Records    dto.AllRecords      `json:"records"`
	}
}

func parseRecordTypes(queryParam string) []string {
	if queryParam == "" {
		return []string{
			"a",
			"aaaa",
			"cname",
			"mx",
			"txt",
			"ns",
			"soa",
			"ptr",
			"srv",
			"caa",
			"dnskey",
			"ds",
			"rrsig",
		}
	}
	return strings.Split(strings.ToLower(queryParam), ",")
}

// handleRecordsList handles the retrieval of DNS records for a domain.
func (app *Server) handleRecordsList(ctx context.Context, i *struct {
	DomainID string `path:"id" example:"domain_00000001" doc:"Domain UID"`
	QType    string `query:"qtype" example:"a,aaaa,cname,mx,txt,ns,doa,ptr,caa,srv,dnskey,ds,rrsig" doc:"Comma-separated list of record types to fetch. Not providing a qtype returns all record types."`
	PaginationQuery
},
) (*RecordsListOutput, error) {
	domain, err := app.Db.DomainsGetByID(ctx, i.DomainID)
	if err != nil {
		return nil, huma.Error404NotFound("domain not found")
	}
	recordTypes := parseRecordTypes(i.QType)

	pageSize, pageNumber, _ := i.PaginationQuery.GetPaginationParams()
	pagination := NewPaginationMetadata(0, pageSize, pageNumber, 0)

	resp := &RecordsListOutput{
		Body: struct {
			Pagination *PaginationMetadata `json:"pagination"`
			Records    dto.AllRecords      `json:"records"`
		}{
			Pagination: &pagination,
			Records: dto.AllRecords{
				DomainName: domain.Name,
				A:          []dto.ARecord{},
				AAAA:       []dto.AAAARecord{},
				CNAME:      []dto.CNAMERecord{},
				MX:         []dto.MXRecord{},
				TXT:        []dto.TXTRecord{},
				NS:         []dto.NSRecord{},
				SOA:        []dto.SOARecord{},
				PTR:        []dto.PTRRecord{},
				CAA:        []dto.CAARecord{},
				SRV:        []dto.SRVRecord{},
				DNSKEY:     []dto.DNSKEYRecord{},
				DS:         []dto.DSRecord{},
				RRSIG:      []dto.RRSIGRecord{},
			},
		},
	}

	// fixme: really inefficient; should be joining not individually querying each table
	// fixme: non-trivially change as SQLc dynamic queries are not straightforward
	var totalRecords int64
	for _, recordType := range recordTypes {
		switch recordType {
		case "a":
			aRecords, err := app.Db.RecordsGetAByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, aR := range aRecords {
					resp.Body.Records.A = append(resp.Body.Records.A, dto.ARecordToAPI(aR))
					totalRecords++
				}
			}
		case "aaaa":
			aaaaRecords, err := app.Db.RecordsGetAAAAByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, aaaaR := range aaaaRecords {
					resp.Body.Records.AAAA = append(
						resp.Body.Records.AAAA,
						dto.AAAARecordToAPI(aaaaR),
					)
					totalRecords++
				}
			}
		case "cname":
			cnameRecords, err := app.Db.RecordsGetCNAMEByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, cR := range cnameRecords {
					resp.Body.Records.CNAME = append(
						resp.Body.Records.CNAME,
						dto.CNAMERecordToAPI(cR),
					)
					totalRecords++
				}
			}
		case "mx":
			mxRecords, err := app.Db.RecordsGetMXByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, mxR := range mxRecords {
					resp.Body.Records.MX = append(resp.Body.Records.MX, dto.MXRecordToAPI(mxR))
					totalRecords++
				}
			}
		case "txt":
			txtRecords, err := app.Db.RecordsGetTXTByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, txtR := range txtRecords {
					resp.Body.Records.TXT = append(resp.Body.Records.TXT, dto.TXTRecordToAPI(txtR))
					totalRecords++
				}
			}
		case "ns":
			nsRecords, err := app.Db.RecordsGetNSByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, nsR := range nsRecords {
					resp.Body.Records.NS = append(resp.Body.Records.NS, dto.NSRecordToAPI(nsR))
					totalRecords++
				}
			}
		case "soa":
			soaRecords, err := app.Db.RecordsGetSOAByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, soaR := range soaRecords {
					resp.Body.Records.SOA = append(resp.Body.Records.SOA, dto.SOARecordToAPI(soaR))
					totalRecords++
				}
			}
		case "ptr":
			ptrRecords, err := app.Db.RecordsGetPTRByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, ptrR := range ptrRecords {
					resp.Body.Records.PTR = append(resp.Body.Records.PTR, dto.PTRRecordToAPI(ptrR))
					totalRecords++
				}
			}
		case "caa":
			caaRecords, err := app.Db.RecordsGetCAAByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, caaR := range caaRecords {
					resp.Body.Records.CAA = append(resp.Body.Records.CAA, dto.CAARecordToAPI(caaR))
					totalRecords++
				}
			}
		case "srv":
			srvRecords, err := app.Db.RecordsGetSRVByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, srvR := range srvRecords {
					resp.Body.Records.SRV = append(resp.Body.Records.SRV, dto.SRVRecordToAPI(srvR))
					totalRecords++
				}
			}
		case "dnskey":
			dnskeyRecords, err := app.Db.RecordsGetDNSKEYByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, dnskeyR := range dnskeyRecords {
					resp.Body.Records.DNSKEY = append(
						resp.Body.Records.DNSKEY,
						dto.DNSKEYRecordToAPI(dnskeyR),
					)
					totalRecords++
				}
			}
		case "ds":
			dsRecords, err := app.Db.RecordsGetDSByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, dsR := range dsRecords {
					resp.Body.Records.DS = append(resp.Body.Records.DS, dto.DSRecordToAPI(dsR))
					totalRecords++
				}
			}
		case "rrsig":
			rrsigRecords, err := app.Db.RecordsGetRRSIGByDomainID(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err == nil {
				for _, rrsigR := range rrsigRecords {
					resp.Body.Records.RRSIG = append(
						resp.Body.Records.RRSIG,
						dto.RRSIGRecordToAPI(rrsigR),
					)
					totalRecords++
				}
			}
		default:
			return nil, huma.Error400BadRequest("invalid record type: " + recordType)
		}
	}

	resp.Body.Pagination.Total = totalRecords
	resp.Body.Pagination.Count = int32(len(recordTypes)) // Not entirely accurate, but gives an idea
	return resp, nil
}
