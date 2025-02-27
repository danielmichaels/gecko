package dto

import (
	"github.com/danielmichaels/gecko/internal/store"
)

// Record types and common fields

// DNSRecord provides common fields for all DNS record types
type DNSRecord struct {
	DomainID  string `json:"domain_id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type ARecord struct {
	DNSRecord
	IPv4Address string `json:"ipv4_address"`
}

type AAAARecord struct {
	DNSRecord
	IPv6Address string `json:"ipv6_address"`
}

type CNAMERecord struct {
	DNSRecord
	Target string `json:"target"`
}

type MXRecord struct {
	DNSRecord
	Preference int32  `json:"preference"`
	Target     string `json:"target"`
}

type TXTRecord struct {
	DNSRecord
	Value string `json:"value"`
}

type NSRecord struct {
	DNSRecord
	Nameserver string `json:"nameserver"`
}

type PTRRecord struct {
	DNSRecord
	Target string `json:"target"`
}

type SOARecord struct {
	DNSRecord
	Nameserver string `json:"nameserver"`
	Email      string `json:"email"`
	Serial     int64  `json:"serial"`
	Refresh    int32  `json:"refresh"`
	Retry      int32  `json:"retry"`
	Expire     int32  `json:"expire"`
	MinimumTTL int32  `json:"minimum_ttl"`
}

type CAARecord struct {
	DNSRecord
	Flags int32  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type SRVRecord struct {
	DNSRecord
	Target   string `json:"target"`
	Port     int32  `json:"port"`
	Weight   int32  `json:"weight"`
	Priority int32  `json:"priority"`
}

type DNSKEYRecord struct {
	DNSRecord
	PublicKey string `json:"public_key"`
	Flags     int32  `json:"flags"`
	Protocol  int32  `json:"protocol"`
	Algorithm int32  `json:"algorithm"`
}

type DSRecord struct {
	DNSRecord
	KeyTag     int32  `json:"key_tag"`
	Algorithm  int32  `json:"algorithm"`
	DigestType int32  `json:"digest_type"`
	Digest     string `json:"digest"`
}

type RRSIGRecord struct {
	DNSRecord
	TypeCovered int32  `json:"type_covered"`
	Algorithm   int32  `json:"algorithm"`
	Labels      int32  `json:"labels"`
	OriginalTTL int32  `json:"original_ttl"`
	Expiration  int32  `json:"expiration"`
	Inception   int32  `json:"inception"`
	KeyTag      int32  `json:"key_tag"`
	SignerName  string `json:"signer_name"`
	Signature   string `json:"signature"`
}

// AllRecords contains all types of DNS records for a domain
type AllRecords struct {
	DomainName string         `json:"domain_name"`
	A          []ARecord      `json:"a,omitempty"`
	AAAA       []AAAARecord   `json:"aaaa,omitempty"`
	CNAME      []CNAMERecord  `json:"cname,omitempty"`
	MX         []MXRecord     `json:"mx,omitempty"`
	TXT        []TXTRecord    `json:"txt,omitempty"`
	NS         []NSRecord     `json:"ns,omitempty"`
	SOA        []SOARecord    `json:"soa,omitempty"`
	PTR        []PTRRecord    `json:"ptr,omitempty"`
	CAA        []CAARecord    `json:"caa,omitempty"`
	SRV        []SRVRecord    `json:"srv,omitempty"`
	DNSKEY     []DNSKEYRecord `json:"dnskey,omitempty"`
	DS         []DSRecord     `json:"ds,omitempty"`
	RRSIG      []RRSIGRecord  `json:"rrsig,omitempty"`
}

// RecordHistory represents a generic history entry for any DNS record
type RecordHistory struct {
	ID         string `json:"id"`
	RecordID   string `json:"record_id"`
	ChangeType string `json:"change_type"` // created, updated, deleted
	Timestamp  string `json:"timestamp"`
	Changes    any    `json:"changes"` // The specific record type data
}

// ARecordToAPI converts store.ARecords to dto.ARecord
func ARecordToAPI(r store.ARecords) ARecord {
	return ARecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		IPv4Address: r.Ipv4Address,
	}
}

// AAAARecordToAPI converts store.AaaaRecords to dto.AAAARecord
func AAAARecordToAPI(r store.AaaaRecords) AAAARecord {
	return AAAARecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		IPv6Address: r.Ipv6Address,
	}
}

// CNAMERecordToAPI converts store.CnameRecords to dto.CNAMERecord
func CNAMERecordToAPI(r store.CnameRecords) CNAMERecord {
	return CNAMERecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		Target: r.Target,
	}
}

// MXRecordToAPI converts store.MxRecords to dto.MXRecord
func MXRecordToAPI(r store.MxRecords) MXRecord {
	return MXRecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		Preference: r.Preference,
		Target:     r.Target,
	}
}

// TXTRecordToAPI converts store.TxtRecords to dto.TXTRecord
func TXTRecordToAPI(r store.TxtRecords) TXTRecord {
	return TXTRecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		Value: r.Value,
	}
}

// NSRecordToAPI converts store.NsRecords to dto.NSRecord
func NSRecordToAPI(r store.NsRecords) NSRecord {
	return NSRecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		Nameserver: r.Nameserver,
	}
}

// SOARecordToAPI converts store.SoaRecords to dto.SOARecord
func SOARecordToAPI(r store.SoaRecords) SOARecord {
	return SOARecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		Nameserver: r.Nameserver,
		Email:      r.Email,
		Serial:     r.Serial,
		Refresh:    r.Refresh,
		Retry:      r.Retry,
		Expire:     r.Expire,
		MinimumTTL: r.MinimumTtl,
	}
}

// PTRRecordToAPI converts store.PtrRecords to dto.PTRRecord
func PTRRecordToAPI(r store.PtrRecords) PTRRecord {
	return PTRRecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		Target: r.Target,
	}
}

// CAARecordToAPI converts store.CaaRecords to dto.CAARecord
func CAARecordToAPI(r store.CaaRecords) CAARecord {
	return CAARecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		Flags: r.Flags,
		Tag:   r.Tag,
		Value: r.Value,
	}
}

// SRVRecordToAPI converts store.SrvRecords to dto.SRVRecord
func SRVRecordToAPI(r store.SrvRecords) SRVRecord {
	return SRVRecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		Target:   r.Target,
		Port:     r.Port,
		Weight:   r.Weight,
		Priority: r.Priority,
	}
}

// DNSKEYRecordToAPI converts store.DnskeyRecords to dto.DNSKEYRecord
func DNSKEYRecordToAPI(r store.DnskeyRecords) DNSKEYRecord {
	return DNSKEYRecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		PublicKey: r.PublicKey,
		Flags:     r.Flags,
		Protocol:  r.Protocol,
		Algorithm: r.Algorithm,
	}
}

// DSRecordToAPI converts store.DsRecords to dto.DSRecord
func DSRecordToAPI(r store.DsRecords) DSRecord {
	return DSRecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		KeyTag:     r.KeyTag,
		Algorithm:  r.Algorithm,
		DigestType: r.DigestType,
		Digest:     r.Digest,
	}
}

// RRSIGRecordToAPI converts store.RrsigRecords to dto.RRSIGRecord
func RRSIGRecordToAPI(r store.RrsigRecords) RRSIGRecord {
	return RRSIGRecord{
		DNSRecord: DNSRecord{
			DomainID:  r.Uid,
			CreatedAt: r.CreatedAt.Time.String(),
			UpdatedAt: r.UpdatedAt.Time.String(),
		},
		TypeCovered: r.TypeCovered,
		Algorithm:   r.Algorithm,
		Labels:      r.Labels,
		OriginalTTL: r.OriginalTtl,
		Expiration:  r.Expiration,
		Inception:   r.Inception,
		KeyTag:      r.KeyTag,
		SignerName:  r.SignerName,
		Signature:   r.Signature,
	}
}

// RecordsGetAllToAPI converts the combined results from RecordsGetAllByDomainID to AllRecords
func RecordsGetAllToAPI(domainName string, records []store.RecordsGetAllByDomainIDRow) AllRecords {
	result := AllRecords{
		DomainName: domainName,
		A:          []ARecord{},
		AAAA:       []AAAARecord{},
		CNAME:      []CNAMERecord{},
		MX:         []MXRecord{},
		TXT:        []TXTRecord{},
		NS:         []NSRecord{},
		SOA:        []SOARecord{},
		PTR:        []PTRRecord{},
		CAA:        []CAARecord{},
		SRV:        []SRVRecord{},
		DNSKEY:     []DNSKEYRecord{},
		DS:         []DSRecord{},
		RRSIG:      []RRSIGRecord{},
	}

	// Process each record row and add to appropriate array
	// This would require more detailed implementation based on how
	// the records are returned from the database

	return result
}
