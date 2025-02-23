package dto

import (
	"fmt"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// DomainToAPI converts a store.Domains model to a Domain API response.
func DomainToAPI(d store.Domains) Domain {
	return Domain{
		ID:         d.Uid,
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

// helper function to safely convert pgtype.Text to string
func pgTextToString(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return ""
}

// helper function to safely convert pgtype.Int4 to int32
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

type Domain struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	DomainType string `json:"domain_type"`
	Source     string `json:"source"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

func (d Domain) String() string {
	return fmt.Sprintf("%-20s %-20s %-10s %-15s %-10s %-25s %-25s",
		d.ID, d.Domain, d.DomainType, d.Source, d.Status, d.CreatedAt, d.UpdatedAt)
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
