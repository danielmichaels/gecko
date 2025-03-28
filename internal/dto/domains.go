package dto

import (
	"fmt"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

type Domain struct {
	UID        string `json:"uid"`
	Domain     string `json:"domain"`
	DomainType string `json:"domain_type"`
	Source     string `json:"source"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

func (d Domain) String() string {
	return fmt.Sprintf("%-20s %-20s %-10s %-15s %-10s %-25s %-25s",
		d.UID, d.Domain, d.DomainType, d.Source, d.Status, d.CreatedAt, d.UpdatedAt)
}

type DomainRecord struct {
	Name        string `json:"name"`
	Ipv4Address string `json:"ipv4_address"`
	Ipv6Address string `json:"ipv6_address"`
	MxTarget    string `json:"mx_target"`
	TxtRecord   string `json:"txt_record"`
	PtrTarget   string `json:"ptr_target"`
	CnameTarget string `json:"cname_target"`
	Nameserver  string `json:"nameserver"`
	MxPref      int32  `json:"mx_pref"`
}

// DomainToAPI converts a store.Domains model to a Domain API response.
func DomainToAPI(d store.Domains) Domain {
	return Domain{
		UID:        d.Uid,
		Domain:     d.Name,
		DomainType: string(d.DomainType),
		Source:     string(d.Source),
		Status:     string(d.Status),
		CreatedAt:  d.CreatedAt.Time.String(),
		UpdatedAt:  d.UpdatedAt.Time.String(),
	}
}

// DomainsToAPI converts a slice of store.Domains models to a slice of Domain API responses.
func DomainsToAPI(domains []store.Domains) []Domain {
	dtos := make([]Domain, len(domains))
	for i, d := range domains {
		dtos[i] = DomainToAPI(d)
	}
	return dtos
}

func pgTextToString(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return ""
}

func pgInt4ToInt32(i pgtype.Int4) int32 {
	if i.Valid {
		return i.Int32
	}
	return 0
}

// DomainRecordsToAPI converts a slice of store.DomainsGetAllRecordsByTenantIDRow to a slice of DomainRecord
func DomainRecordsToAPI(records []store.DomainsGetAllRecordsByTenantIDRow) []DomainRecord {
	dtos := make([]DomainRecord, len(records))
	for i, r := range records {
		dtos[i] = DomainRecord{
			Name:        r.Name,
			Ipv4Address: pgTextToString(r.Ipv4Address),
			Ipv6Address: pgTextToString(r.Ipv6Address),
			MxPref:      pgInt4ToInt32(r.MxPref),
			MxTarget:    pgTextToString(r.MxTarget),
			TxtRecord:   pgTextToString(r.TxtRecord),
			PtrTarget:   pgTextToString(r.PtrTarget),
			CnameTarget: pgTextToString(r.CnameTarget),
			Nameserver:  pgTextToString(r.Nameserver),
		}
	}
	return dtos
}

// DomainSearchByNameRowToDomains converts a slice of store.DomainsSearchByNameRow to a slice of store.Domains.
// It iterates over the input slice and creates a new slice of store.Domains, populating the fields
// from the corresponding fields in the input slice.
func DomainSearchByNameRowToDomains(rows []store.DomainsSearchByNameRow) []store.Domains {
	domains := make([]store.Domains, len(rows))
	for i, row := range rows {
		domains[i] = store.Domains{
			ID:         row.ID,
			Uid:        row.Uid,
			TenantID:   row.TenantID,
			Name:       row.Name,
			DomainType: row.DomainType,
			Source:     row.Source,
			Status:     row.Status,
			CreatedAt:  row.CreatedAt,
			UpdatedAt:  row.UpdatedAt,
		}
	}
	return domains
}

// DomainsListByTenantIDToDomains converts a slice of store.DomainsListByTenantIDRow to a slice of store.Domains.
// It iterates over the input slice and creates a new slice of store.Domains, populating the fields
// from the corresponding fields in the input slice.
func DomainsListByTenantIDToDomains(rows []store.DomainsListByTenantIDRow) []store.Domains {
	domains := make([]store.Domains, len(rows))
	for i, row := range rows {
		domains[i] = store.Domains{
			ID:         row.ID,
			Uid:        row.Uid,
			TenantID:   row.TenantID,
			Name:       row.Name,
			DomainType: row.DomainType,
			Source:     row.Source,
			Status:     row.Status,
			CreatedAt:  row.CreatedAt,
			UpdatedAt:  row.UpdatedAt,
		}
	}
	return domains
}
