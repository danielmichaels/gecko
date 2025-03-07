// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package store

import (
	"database/sql/driver"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
)

type DomainSource string

const (
	DomainSourceUserSupplied DomainSource = "user_supplied"
	DomainSourceDiscovered   DomainSource = "discovered"
)

func (e *DomainSource) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = DomainSource(s)
	case string:
		*e = DomainSource(s)
	default:
		return fmt.Errorf("unsupported scan type for DomainSource: %T", src)
	}
	return nil
}

type NullDomainSource struct {
	DomainSource DomainSource `json:"domain_source"`
	Valid        bool         `json:"valid"` // Valid is true if DomainSource is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullDomainSource) Scan(value interface{}) error {
	if value == nil {
		ns.DomainSource, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.DomainSource.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullDomainSource) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.DomainSource), nil
}

type DomainStatus string

const (
	DomainStatusActive   DomainStatus = "active"
	DomainStatusInactive DomainStatus = "inactive"
	DomainStatusPending  DomainStatus = "pending"
)

func (e *DomainStatus) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = DomainStatus(s)
	case string:
		*e = DomainStatus(s)
	default:
		return fmt.Errorf("unsupported scan type for DomainStatus: %T", src)
	}
	return nil
}

type NullDomainStatus struct {
	DomainStatus DomainStatus `json:"domain_status"`
	Valid        bool         `json:"valid"` // Valid is true if DomainStatus is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullDomainStatus) Scan(value interface{}) error {
	if value == nil {
		ns.DomainStatus, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.DomainStatus.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullDomainStatus) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.DomainStatus), nil
}

type DomainType string

const (
	DomainTypeTld       DomainType = "tld"
	DomainTypeSubdomain DomainType = "subdomain"
	DomainTypeWildcard  DomainType = "wildcard"
	DomainTypeOld       DomainType = "old"
	DomainTypeOther     DomainType = "other"
)

func (e *DomainType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = DomainType(s)
	case string:
		*e = DomainType(s)
	default:
		return fmt.Errorf("unsupported scan type for DomainType: %T", src)
	}
	return nil
}

type NullDomainType struct {
	DomainType DomainType `json:"domain_type"`
	Valid      bool       `json:"valid"` // Valid is true if DomainType is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullDomainType) Scan(value interface{}) error {
	if value == nil {
		ns.DomainType, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.DomainType.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullDomainType) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.DomainType), nil
}

type UserRole string

const (
	UserRoleOwner      UserRole = "owner"
	UserRoleManager    UserRole = "manager"
	UserRoleViewer     UserRole = "viewer"
	UserRoleSuperadmin UserRole = "superadmin"
)

func (e *UserRole) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = UserRole(s)
	case string:
		*e = UserRole(s)
	default:
		return fmt.Errorf("unsupported scan type for UserRole: %T", src)
	}
	return nil
}

type NullUserRole struct {
	UserRole UserRole `json:"user_role"`
	Valid    bool     `json:"valid"` // Valid is true if UserRole is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullUserRole) Scan(value interface{}) error {
	if value == nil {
		ns.UserRole, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.UserRole.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullUserRole) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.UserRole), nil
}

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusPending  UserStatus = "pending"
)

func (e *UserStatus) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = UserStatus(s)
	case string:
		*e = UserStatus(s)
	default:
		return fmt.Errorf("unsupported scan type for UserStatus: %T", src)
	}
	return nil
}

type NullUserStatus struct {
	UserStatus UserStatus `json:"user_status"`
	Valid      bool       `json:"valid"` // Valid is true if UserStatus is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullUserStatus) Scan(value interface{}) error {
	if value == nil {
		ns.UserStatus, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.UserStatus.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullUserStatus) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.UserStatus), nil
}

type ARecords struct {
	ID          int32              `json:"id"`
	Uid         string             `json:"uid"`
	DomainID    pgtype.Int4        `json:"domain_id"`
	Ipv4Address string             `json:"ipv4_address"`
	CreatedAt   pgtype.Timestamptz `json:"created_at"`
	UpdatedAt   pgtype.Timestamptz `json:"updated_at"`
}

type ARecordsHistory struct {
	ID          int32              `json:"id"`
	RecordID    pgtype.Int4        `json:"record_id"`
	Ipv4Address string             `json:"ipv4_address"`
	ChangeType  string             `json:"change_type"`
	ChangedAt   pgtype.Timestamptz `json:"changed_at"`
}

type AaaaRecords struct {
	ID          int32              `json:"id"`
	Uid         string             `json:"uid"`
	DomainID    pgtype.Int4        `json:"domain_id"`
	Ipv6Address string             `json:"ipv6_address"`
	CreatedAt   pgtype.Timestamptz `json:"created_at"`
	UpdatedAt   pgtype.Timestamptz `json:"updated_at"`
}

type AaaaRecordsHistory struct {
	ID          int32              `json:"id"`
	RecordID    pgtype.Int4        `json:"record_id"`
	Ipv6Address string             `json:"ipv6_address"`
	ChangeType  string             `json:"change_type"`
	ChangedAt   pgtype.Timestamptz `json:"changed_at"`
}

type CaaRecords struct {
	ID        int32              `json:"id"`
	Uid       string             `json:"uid"`
	DomainID  pgtype.Int4        `json:"domain_id"`
	Flags     int32              `json:"flags"`
	Tag       string             `json:"tag"`
	Value     string             `json:"value"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

type CaaRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	Flags      int32              `json:"flags"`
	Tag        string             `json:"tag"`
	Value      string             `json:"value"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type Certificates struct {
	ID            int32              `json:"id"`
	Uid           string             `json:"uid"`
	DomainID      pgtype.Int4        `json:"domain_id"`
	NotBefore     pgtype.Timestamptz `json:"not_before"`
	NotAfter      pgtype.Timestamptz `json:"not_after"`
	Issuer        string             `json:"issuer"`
	IssuerOrgName pgtype.Text        `json:"issuer_org_name"`
	IssuerCountry pgtype.Text        `json:"issuer_country"`
	Subject       string             `json:"subject"`
	KeyAlgorithm  string             `json:"key_algorithm"`
	KeyStrength   int32              `json:"key_strength"`
	Sans          []string           `json:"sans"`
	DnsNames      []string           `json:"dns_names"`
	IsCa          bool               `json:"is_ca"`
	IssuerCertUrl []string           `json:"issuer_cert_url"`
	CipherSuite   string             `json:"cipher_suite"`
	TlsVersion    string             `json:"tls_version"`
	CreatedAt     pgtype.Timestamptz `json:"created_at"`
	UpdatedAt     pgtype.Timestamptz `json:"updated_at"`
}

type CertificatesHistory struct {
	ID            int32              `json:"id"`
	RecordID      pgtype.Int4        `json:"record_id"`
	NotBefore     pgtype.Timestamptz `json:"not_before"`
	NotAfter      pgtype.Timestamptz `json:"not_after"`
	Issuer        string             `json:"issuer"`
	IssuerOrgName pgtype.Text        `json:"issuer_org_name"`
	IssuerCountry pgtype.Text        `json:"issuer_country"`
	Subject       string             `json:"subject"`
	KeyAlgorithm  string             `json:"key_algorithm"`
	KeyStrength   int32              `json:"key_strength"`
	Sans          []string           `json:"sans"`
	DnsNames      []string           `json:"dns_names"`
	IsCa          bool               `json:"is_ca"`
	IssuerCertUrl []string           `json:"issuer_cert_url"`
	CipherSuite   string             `json:"cipher_suite"`
	TlsVersion    string             `json:"tls_version"`
	ChangeType    string             `json:"change_type"`
	ChangedAt     pgtype.Timestamptz `json:"changed_at"`
}

type CnameRecords struct {
	ID        int32              `json:"id"`
	Uid       string             `json:"uid"`
	DomainID  pgtype.Int4        `json:"domain_id"`
	Target    string             `json:"target"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

type CnameRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	Target     string             `json:"target"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type DnskeyRecords struct {
	ID        int32              `json:"id"`
	Uid       string             `json:"uid"`
	DomainID  pgtype.Int4        `json:"domain_id"`
	PublicKey string             `json:"public_key"`
	Flags     int32              `json:"flags"`
	Protocol  int32              `json:"protocol"`
	Algorithm int32              `json:"algorithm"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

type DnskeyRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	PublicKey  string             `json:"public_key"`
	Flags      int32              `json:"flags"`
	Protocol   int32              `json:"protocol"`
	Algorithm  int32              `json:"algorithm"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type Domains struct {
	ID             int32              `json:"id"`
	Uid            string             `json:"uid"`
	TenantID       pgtype.Int4        `json:"tenant_id"`
	Name           string             `json:"name"`
	DomainType     DomainType         `json:"domain_type"`
	Source         DomainSource       `json:"source"`
	Status         DomainStatus       `json:"status"`
	CreatedAt      pgtype.Timestamptz `json:"created_at"`
	UpdatedAt      pgtype.Timestamptz `json:"updated_at"`
	ParentDomainID pgtype.Int4        `json:"parent_domain_id"`
}

type DsRecords struct {
	ID         int32              `json:"id"`
	Uid        string             `json:"uid"`
	DomainID   pgtype.Int4        `json:"domain_id"`
	KeyTag     int32              `json:"key_tag"`
	Algorithm  int32              `json:"algorithm"`
	DigestType int32              `json:"digest_type"`
	Digest     string             `json:"digest"`
	CreatedAt  pgtype.Timestamptz `json:"created_at"`
	UpdatedAt  pgtype.Timestamptz `json:"updated_at"`
}

type DsRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	KeyTag     int32              `json:"key_tag"`
	Algorithm  int32              `json:"algorithm"`
	DigestType int32              `json:"digest_type"`
	Digest     string             `json:"digest"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type MxRecords struct {
	ID         int32              `json:"id"`
	Uid        string             `json:"uid"`
	DomainID   pgtype.Int4        `json:"domain_id"`
	Preference int32              `json:"preference"`
	Target     string             `json:"target"`
	CreatedAt  pgtype.Timestamptz `json:"created_at"`
	UpdatedAt  pgtype.Timestamptz `json:"updated_at"`
}

type MxRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	Preference int32              `json:"preference"`
	Target     string             `json:"target"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type NsRecords struct {
	ID         int32              `json:"id"`
	Uid        string             `json:"uid"`
	DomainID   pgtype.Int4        `json:"domain_id"`
	Nameserver string             `json:"nameserver"`
	CreatedAt  pgtype.Timestamptz `json:"created_at"`
	UpdatedAt  pgtype.Timestamptz `json:"updated_at"`
}

type NsRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	Nameserver string             `json:"nameserver"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type PtrRecords struct {
	ID        int32              `json:"id"`
	Uid       string             `json:"uid"`
	DomainID  pgtype.Int4        `json:"domain_id"`
	Target    string             `json:"target"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

type PtrRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	Target     string             `json:"target"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type RrsigRecords struct {
	ID          int32              `json:"id"`
	Uid         string             `json:"uid"`
	DomainID    pgtype.Int4        `json:"domain_id"`
	TypeCovered int32              `json:"type_covered"`
	Algorithm   int32              `json:"algorithm"`
	Labels      int32              `json:"labels"`
	OriginalTtl int32              `json:"original_ttl"`
	Expiration  int32              `json:"expiration"`
	Inception   int32              `json:"inception"`
	KeyTag      int32              `json:"key_tag"`
	SignerName  string             `json:"signer_name"`
	Signature   string             `json:"signature"`
	CreatedAt   pgtype.Timestamptz `json:"created_at"`
	UpdatedAt   pgtype.Timestamptz `json:"updated_at"`
}

type RrsigRecordsHistory struct {
	ID          int32              `json:"id"`
	RecordID    pgtype.Int4        `json:"record_id"`
	TypeCovered int32              `json:"type_covered"`
	Algorithm   int32              `json:"algorithm"`
	Labels      int32              `json:"labels"`
	OriginalTtl int32              `json:"original_ttl"`
	Expiration  int32              `json:"expiration"`
	Inception   int32              `json:"inception"`
	KeyTag      int32              `json:"key_tag"`
	SignerName  string             `json:"signer_name"`
	Signature   string             `json:"signature"`
	ChangeType  string             `json:"change_type"`
	ChangedAt   pgtype.Timestamptz `json:"changed_at"`
}

type SoaRecords struct {
	ID         int32              `json:"id"`
	Uid        string             `json:"uid"`
	DomainID   pgtype.Int4        `json:"domain_id"`
	Nameserver string             `json:"nameserver"`
	Email      string             `json:"email"`
	Serial     int64              `json:"serial"`
	Refresh    int32              `json:"refresh"`
	Retry      int32              `json:"retry"`
	Expire     int32              `json:"expire"`
	MinimumTtl int32              `json:"minimum_ttl"`
	CreatedAt  pgtype.Timestamptz `json:"created_at"`
	UpdatedAt  pgtype.Timestamptz `json:"updated_at"`
}

type SoaRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	Nameserver string             `json:"nameserver"`
	Email      string             `json:"email"`
	Serial     int64              `json:"serial"`
	Refresh    int32              `json:"refresh"`
	Retry      int32              `json:"retry"`
	Expire     int32              `json:"expire"`
	MinimumTtl int32              `json:"minimum_ttl"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type SrvRecords struct {
	ID        int32              `json:"id"`
	Uid       string             `json:"uid"`
	DomainID  pgtype.Int4        `json:"domain_id"`
	Target    string             `json:"target"`
	Port      int32              `json:"port"`
	Weight    int32              `json:"weight"`
	Priority  int32              `json:"priority"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

type SrvRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	Target     string             `json:"target"`
	Port       int32              `json:"port"`
	Weight     int32              `json:"weight"`
	Priority   int32              `json:"priority"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type Tenants struct {
	ID        int32              `json:"id"`
	Uid       string             `json:"uid"`
	Name      string             `json:"name"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

type TxtRecords struct {
	ID        int32              `json:"id"`
	Uid       string             `json:"uid"`
	DomainID  pgtype.Int4        `json:"domain_id"`
	Value     string             `json:"value"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}

type TxtRecordsHistory struct {
	ID         int32              `json:"id"`
	RecordID   pgtype.Int4        `json:"record_id"`
	Value      string             `json:"value"`
	ChangeType string             `json:"change_type"`
	ChangedAt  pgtype.Timestamptz `json:"changed_at"`
}

type Users struct {
	ID        int32              `json:"id"`
	Uid       string             `json:"uid"`
	TenantID  pgtype.Int4        `json:"tenant_id"`
	Email     string             `json:"email"`
	Name      pgtype.Text        `json:"name"`
	Role      UserRole           `json:"role"`
	Status    string             `json:"status"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
	UpdatedAt pgtype.Timestamptz `json:"updated_at"`
}
