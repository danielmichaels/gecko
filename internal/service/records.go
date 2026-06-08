package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// RecordsService exposes DNS record read operations.
type RecordsService struct {
	*Service
}

// qtypeToEntityType maps the API's record qtype filter onto the entity_type the
// recorder writes into the observation log. Values reference the observer
// constants so a rename can't silently desync the filter from what is stored.
var qtypeToEntityType = map[string]string{
	"a":      observer.EntityARecord,
	"aaaa":   observer.EntityAAAARecord,
	"cname":  observer.EntityCNAMERecord,
	"mx":     observer.EntityMXRecord,
	"txt":    observer.EntityTXTRecord,
	"ns":     observer.EntityNSRecord,
	"soa":    observer.EntitySOARecord,
	"ptr":    observer.EntityPTRRecord,
	"caa":    observer.EntityCAARecord,
	"srv":    observer.EntitySRVRecord,
	"dnskey": observer.EntityDNSKEYRecord,
	"ds":     observer.EntityDSRecord,
	"rrsig":  observer.EntityRRSIGRecord,
}

// defaultRecordTypes lists all supported qtype values returned when no filter
// is provided.
var defaultRecordTypes = []string{
	"a", "aaaa", "cname", "mx", "txt", "ns", "soa", "ptr", "srv", "caa",
	"dnskey", "ds", "rrsig",
}

// ParseRecordTypes converts a comma-separated qtype query param into a slice.
// An empty string returns all supported types.
func ParseRecordTypes(queryParam string) []string {
	if queryParam == "" {
		return defaultRecordTypes
	}
	return strings.Split(strings.ToLower(queryParam), ",")
}

// RecordsListResult bundles the AllRecords payload with a total count.
type RecordsListResult struct {
	Records      dto.AllRecords
	TotalRecords int64
}

// List returns current DNS records for the given domain, filtered by recordTypes.
// recordTypes nil/empty means all types. Invalid type → ErrInvalidInput.
//
// fixme: really inefficient; should be joining not individually querying each table
// fixme: non-trivially change as SQLc dynamic queries are not straightforward
func (s *RecordsService) List(
	ctx context.Context,
	p *auth.Principal,
	domainUID string,
	recordTypes []string,
) (RecordsListResult, error) {
	domain, err := s.DB.DomainsGetByID(ctx, store.DomainsGetByIDParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		return RecordsListResult{}, ErrNotFound
	}

	if len(recordTypes) == 0 {
		recordTypes = defaultRecordTypes
	}

	records := dto.AllRecords{
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
	}

	domainIDParam := pgtype.Int4{Int32: domain.ID, Valid: true}
	var total int64

	for _, rt := range recordTypes {
		switch rt {
		case "a":
			rows, err := s.DB.RecordsGetAByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.A = append(records.A, dto.ARecordToAPI(r))
					total++
				}
			}
		case "aaaa":
			rows, err := s.DB.RecordsGetAAAAByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.AAAA = append(records.AAAA, dto.AAAARecordToAPI(r))
					total++
				}
			}
		case "cname":
			rows, err := s.DB.RecordsGetCNAMEByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.CNAME = append(records.CNAME, dto.CNAMERecordToAPI(r))
					total++
				}
			}
		case "mx":
			rows, err := s.DB.RecordsGetMXByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.MX = append(records.MX, dto.MXRecordToAPI(r))
					total++
				}
			}
		case "txt":
			rows, err := s.DB.RecordsGetTXTByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.TXT = append(records.TXT, dto.TXTRecordToAPI(r))
					total++
				}
			}
		case "ns":
			rows, err := s.DB.RecordsGetNSByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.NS = append(records.NS, dto.NSRecordToAPI(r))
					total++
				}
			}
		case "soa":
			rows, err := s.DB.RecordsGetSOAByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.SOA = append(records.SOA, dto.SOARecordToAPI(r))
					total++
				}
			}
		case "ptr":
			rows, err := s.DB.RecordsGetPTRByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.PTR = append(records.PTR, dto.PTRRecordToAPI(r))
					total++
				}
			}
		case "caa":
			rows, err := s.DB.RecordsGetCAAByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.CAA = append(records.CAA, dto.CAARecordToAPI(r))
					total++
				}
			}
		case "srv":
			rows, err := s.DB.RecordsGetSRVByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.SRV = append(records.SRV, dto.SRVRecordToAPI(r))
					total++
				}
			}
		case "dnskey":
			rows, err := s.DB.RecordsGetDNSKEYByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.DNSKEY = append(records.DNSKEY, dto.DNSKEYRecordToAPI(r))
					total++
				}
			}
		case "ds":
			rows, err := s.DB.RecordsGetDSByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.DS = append(records.DS, dto.DSRecordToAPI(r))
					total++
				}
			}
		case "rrsig":
			rows, err := s.DB.RecordsGetRRSIGByDomainID(ctx, domainIDParam)
			if err == nil {
				for _, r := range rows {
					records.RRSIG = append(records.RRSIG, dto.RRSIGRecordToAPI(r))
					total++
				}
			}
		default:
			return RecordsListResult{}, fmt.Errorf("%w: %s", ErrInvalidInput, rt)
		}
	}

	return RecordsListResult{Records: records, TotalRecords: total}, nil
}

// HistoryResult holds the domain name and flat change log for the caller.
type HistoryResult struct {
	DomainName string
	History    []dto.RecordHistory
}

// History returns the observation log for the given domain, optionally filtered
// by a comma-separated qtype string. Invalid type → ErrInvalidInput.
//
// It resolves the {id} to its (tenant_id, name) and queries observations by
// that key — never the live domain_id, which goes NULL on delete — so a
// re-added domain shows its prior timeline and a deleted domain's history stays
// reachable.
func (s *RecordsService) History(
	ctx context.Context,
	p *auth.Principal,
	domainUID string,
	qtypeFilter string,
) (HistoryResult, error) {
	domain, err := s.DB.DomainsGetByID(ctx, store.DomainsGetByIDParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		return HistoryResult{}, ErrNotFound
	}

	var wanted map[string]bool
	if qtypeFilter != "" {
		wanted = make(map[string]bool)
		for _, q := range strings.Split(strings.ToLower(qtypeFilter), ",") {
			et, ok := qtypeToEntityType[q]
			if !ok {
				return HistoryResult{}, fmt.Errorf("%w: %s", ErrInvalidInput, q)
			}
			wanted[et] = true
		}
	}

	obs, err := s.DB.ObservationsListWithScanUIDByTenantDomainName(
		ctx,
		store.ObservationsListWithScanUIDByTenantDomainNameParams{
			TenantID:   domain.TenantID.Int32,
			DomainName: domain.Name,
		},
	)
	if err != nil {
		return HistoryResult{}, fmt.Errorf("load record history: %w", err)
	}

	history := []dto.RecordHistory{}
	for _, o := range obs {
		if wanted != nil && !wanted[o.EntityType] {
			continue
		}
		history = append(history, dto.ObsWithScanRowToRecordHistory(o))
	}

	return HistoryResult{DomainName: domain.Name, History: history}, nil
}

// TimelineResult holds the domain name and scan-grouped change timeline.
type TimelineResult struct {
	DomainName string
	Scans      []dto.ScanDiff
}

// Timeline returns a domain's scan-by-scan change timeline: every scan that
// recorded a change (newest first) with the observations from it, grouped by
// scan uid. Keyed on (tenant_id, domain_name) so it survives a domain
// delete/re-add, and carries parent_scan_uid lineage so child (discovered) scans
// can be nested under the apex scan that found them. A single join query supplies
// both the changes and their scan metadata; scans with no observations never
// appear, so the timeline reads as a pure change history.
func (s *RecordsService) Timeline(
	ctx context.Context,
	p *auth.Principal,
	domainUID string,
) (TimelineResult, error) {
	domain, err := s.DB.DomainsGetByID(ctx, store.DomainsGetByIDParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		return TimelineResult{}, ErrNotFound
	}

	rows, err := s.DB.ObservationsListTimelineByTenantDomainName(
		ctx,
		store.ObservationsListTimelineByTenantDomainNameParams{
			TenantID:   domain.TenantID.Int32,
			DomainName: domain.Name,
		},
	)
	if err != nil {
		return TimelineResult{}, fmt.Errorf("load timeline: %w", err)
	}

	scans := []dto.ScanDiff{}

	// Rows arrive ordered newest-scan-first, then by observation id, so grouping
	// by first-seen scan uid preserves both scan order and change order.
	byUID := map[string]int{}
	for _, row := range rows {
		idx, seen := byUID[row.ScanUid]
		if !seen {
			sd := dto.ScanDiff{
				ScanUID: row.ScanUid,
				Source:  string(row.ScanSource),
				Changes: []dto.RecordHistory{},
			}
			if row.ScanStartedAt.Valid {
				sd.StartedAt = row.ScanStartedAt.Time.Format(time.RFC3339)
			}
			if row.ParentScanUid.Valid {
				sd.ParentScanUID = row.ParentScanUid.String
			}
			scans = append(scans, sd)
			idx = len(scans) - 1
			byUID[row.ScanUid] = idx
		}
		scans[idx].Changes = append(scans[idx].Changes, dto.TimelineRowToRecordHistory(row))
	}

	return TimelineResult{DomainName: domain.Name, Scans: scans}, nil
}
