// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: records.sql

package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const recordsCreateA = `-- name: RecordsCreateA :one
INSERT INTO a_records (domain_id, ipv4_address)
VALUES ($1, $2)
ON CONFLICT (domain_id, ipv4_address)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, ipv4_address, created_at, updated_at
`

type RecordsCreateAParams struct {
	DomainID    pgtype.Int4 `json:"domain_id"`
	Ipv4Address string      `json:"ipv4_address"`
}

// A Records
func (q *Queries) RecordsCreateA(ctx context.Context, arg RecordsCreateAParams) (ARecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateA, arg.DomainID, arg.Ipv4Address)
	var i ARecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Ipv4Address,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateAAAA = `-- name: RecordsCreateAAAA :one
INSERT INTO aaaa_records (domain_id, ipv6_address)
VALUES ($1, $2)
ON CONFLICT (domain_id, ipv6_address)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, ipv6_address, created_at, updated_at
`

type RecordsCreateAAAAParams struct {
	DomainID    pgtype.Int4 `json:"domain_id"`
	Ipv6Address string      `json:"ipv6_address"`
}

// AAAA Records
func (q *Queries) RecordsCreateAAAA(ctx context.Context, arg RecordsCreateAAAAParams) (AaaaRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateAAAA, arg.DomainID, arg.Ipv6Address)
	var i AaaaRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Ipv6Address,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateCAA = `-- name: RecordsCreateCAA :one
INSERT INTO caa_records (domain_id, flags, tag, value)
VALUES ($1, $2, $3, $4)
ON CONFLICT (domain_id, tag, value)
    DO UPDATE SET flags      = $2,
                  updated_at = NOW()
RETURNING id, uid, domain_id, flags, tag, value, created_at, updated_at
`

type RecordsCreateCAAParams struct {
	DomainID pgtype.Int4 `json:"domain_id"`
	Flags    int32       `json:"flags"`
	Tag      string      `json:"tag"`
	Value    string      `json:"value"`
}

// CAA Records
func (q *Queries) RecordsCreateCAA(ctx context.Context, arg RecordsCreateCAAParams) (CaaRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateCAA,
		arg.DomainID,
		arg.Flags,
		arg.Tag,
		arg.Value,
	)
	var i CaaRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Flags,
		&i.Tag,
		&i.Value,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateCNAME = `-- name: RecordsCreateCNAME :one
INSERT INTO cname_records (domain_id, target)
VALUES ($1, $2)
ON CONFLICT (domain_id, target)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, target, created_at, updated_at
`

type RecordsCreateCNAMEParams struct {
	DomainID pgtype.Int4 `json:"domain_id"`
	Target   string      `json:"target"`
}

// CNAME Records
func (q *Queries) RecordsCreateCNAME(ctx context.Context, arg RecordsCreateCNAMEParams) (CnameRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateCNAME, arg.DomainID, arg.Target)
	var i CnameRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Target,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateDNSKEY = `-- name: RecordsCreateDNSKEY :one
INSERT INTO dnskey_records (domain_id, public_key, flags, protocol, algorithm)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (domain_id, public_key)
    DO UPDATE SET flags      = $3,
                  protocol   = $4,
                  algorithm  = $5,
                  updated_at = NOW()
RETURNING id, uid, domain_id, public_key, flags, protocol, algorithm, created_at, updated_at
`

type RecordsCreateDNSKEYParams struct {
	DomainID  pgtype.Int4 `json:"domain_id"`
	PublicKey string      `json:"public_key"`
	Flags     int32       `json:"flags"`
	Protocol  int32       `json:"protocol"`
	Algorithm int32       `json:"algorithm"`
}

func (q *Queries) RecordsCreateDNSKEY(ctx context.Context, arg RecordsCreateDNSKEYParams) (DnskeyRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateDNSKEY,
		arg.DomainID,
		arg.PublicKey,
		arg.Flags,
		arg.Protocol,
		arg.Algorithm,
	)
	var i DnskeyRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.PublicKey,
		&i.Flags,
		&i.Protocol,
		&i.Algorithm,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateDS = `-- name: RecordsCreateDS :one
INSERT INTO ds_records (domain_id, key_tag, algorithm, digest_type, digest)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (domain_id, digest)
    DO UPDATE SET key_tag     = $2,
                  algorithm   = $3,
                  digest_type = $4,
                  updated_at  = NOW()
RETURNING id, uid, domain_id, key_tag, algorithm, digest_type, digest, created_at, updated_at
`

type RecordsCreateDSParams struct {
	DomainID   pgtype.Int4 `json:"domain_id"`
	KeyTag     int32       `json:"key_tag"`
	Algorithm  int32       `json:"algorithm"`
	DigestType int32       `json:"digest_type"`
	Digest     string      `json:"digest"`
}

// DS Records
func (q *Queries) RecordsCreateDS(ctx context.Context, arg RecordsCreateDSParams) (DsRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateDS,
		arg.DomainID,
		arg.KeyTag,
		arg.Algorithm,
		arg.DigestType,
		arg.Digest,
	)
	var i DsRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.KeyTag,
		&i.Algorithm,
		&i.DigestType,
		&i.Digest,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateMX = `-- name: RecordsCreateMX :one
INSERT INTO mx_records (domain_id, preference, target)
VALUES ($1, $2, $3)
ON CONFLICT (domain_id, preference, target)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, preference, target, created_at, updated_at
`

type RecordsCreateMXParams struct {
	DomainID   pgtype.Int4 `json:"domain_id"`
	Preference int32       `json:"preference"`
	Target     string      `json:"target"`
}

// MX Records
func (q *Queries) RecordsCreateMX(ctx context.Context, arg RecordsCreateMXParams) (MxRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateMX, arg.DomainID, arg.Preference, arg.Target)
	var i MxRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Preference,
		&i.Target,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateNS = `-- name: RecordsCreateNS :one
INSERT INTO ns_records (domain_id, nameserver)
VALUES ($1, $2)
ON CONFLICT (domain_id, nameserver)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, nameserver, created_at, updated_at
`

type RecordsCreateNSParams struct {
	DomainID   pgtype.Int4 `json:"domain_id"`
	Nameserver string      `json:"nameserver"`
}

// NS Records
func (q *Queries) RecordsCreateNS(ctx context.Context, arg RecordsCreateNSParams) (NsRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateNS, arg.DomainID, arg.Nameserver)
	var i NsRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Nameserver,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreatePTR = `-- name: RecordsCreatePTR :one
INSERT INTO ptr_records (domain_id, target)
VALUES ($1, $2)
ON CONFLICT (domain_id, target)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, target, created_at, updated_at
`

type RecordsCreatePTRParams struct {
	DomainID pgtype.Int4 `json:"domain_id"`
	Target   string      `json:"target"`
}

// PTR Records
func (q *Queries) RecordsCreatePTR(ctx context.Context, arg RecordsCreatePTRParams) (PtrRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreatePTR, arg.DomainID, arg.Target)
	var i PtrRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Target,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateRRSIG = `-- name: RecordsCreateRRSIG :one
INSERT INTO rrsig_records (domain_id, type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag,
                           signer_name, signature)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (domain_id, type_covered, signer_name)
    DO UPDATE SET algorithm    = $3,
                  labels       = $4,
                  original_ttl = $5,
                  expiration   = $6,
                  inception    = $7,
                  key_tag      = $8,
                  signature    = $10,
                  updated_at   = NOW()
RETURNING id, uid, domain_id, type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer_name, signature, created_at, updated_at
`

type RecordsCreateRRSIGParams struct {
	DomainID    pgtype.Int4 `json:"domain_id"`
	TypeCovered int32       `json:"type_covered"`
	Algorithm   int32       `json:"algorithm"`
	Labels      int32       `json:"labels"`
	OriginalTtl int32       `json:"original_ttl"`
	Expiration  int32       `json:"expiration"`
	Inception   int32       `json:"inception"`
	KeyTag      int32       `json:"key_tag"`
	SignerName  string      `json:"signer_name"`
	Signature   string      `json:"signature"`
}

// RRSIG Records
func (q *Queries) RecordsCreateRRSIG(ctx context.Context, arg RecordsCreateRRSIGParams) (RrsigRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateRRSIG,
		arg.DomainID,
		arg.TypeCovered,
		arg.Algorithm,
		arg.Labels,
		arg.OriginalTtl,
		arg.Expiration,
		arg.Inception,
		arg.KeyTag,
		arg.SignerName,
		arg.Signature,
	)
	var i RrsigRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.TypeCovered,
		&i.Algorithm,
		&i.Labels,
		&i.OriginalTtl,
		&i.Expiration,
		&i.Inception,
		&i.KeyTag,
		&i.SignerName,
		&i.Signature,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateSOA = `-- name: RecordsCreateSOA :one
INSERT INTO soa_records (domain_id, nameserver, email, serial, refresh, retry, expire, minimum_ttl)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (domain_id)
    DO UPDATE SET nameserver  = $2,
                  email       = $3,
                  serial      = $4,
                  refresh     = $5,
                  retry       = $6,
                  expire      = $7,
                  minimum_ttl = $8,
                  updated_at  = NOW()
RETURNING id, uid, domain_id, nameserver, email, serial, refresh, retry, expire, minimum_ttl, created_at, updated_at
`

type RecordsCreateSOAParams struct {
	DomainID   pgtype.Int4 `json:"domain_id"`
	Nameserver string      `json:"nameserver"`
	Email      string      `json:"email"`
	Serial     int64       `json:"serial"`
	Refresh    int32       `json:"refresh"`
	Retry      int32       `json:"retry"`
	Expire     int32       `json:"expire"`
	MinimumTtl int32       `json:"minimum_ttl"`
}

func (q *Queries) RecordsCreateSOA(ctx context.Context, arg RecordsCreateSOAParams) (SoaRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateSOA,
		arg.DomainID,
		arg.Nameserver,
		arg.Email,
		arg.Serial,
		arg.Refresh,
		arg.Retry,
		arg.Expire,
		arg.MinimumTtl,
	)
	var i SoaRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Nameserver,
		&i.Email,
		&i.Serial,
		&i.Refresh,
		&i.Retry,
		&i.Expire,
		&i.MinimumTtl,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateSRV = `-- name: RecordsCreateSRV :one
INSERT INTO srv_records (domain_id, target, port, weight, priority)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (domain_id, target, port, priority)
    DO UPDATE SET weight     = $4,
                  updated_at = NOW()
RETURNING id, uid, domain_id, target, port, weight, priority, created_at, updated_at
`

type RecordsCreateSRVParams struct {
	DomainID pgtype.Int4 `json:"domain_id"`
	Target   string      `json:"target"`
	Port     int32       `json:"port"`
	Weight   int32       `json:"weight"`
	Priority int32       `json:"priority"`
}

func (q *Queries) RecordsCreateSRV(ctx context.Context, arg RecordsCreateSRVParams) (SrvRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateSRV,
		arg.DomainID,
		arg.Target,
		arg.Port,
		arg.Weight,
		arg.Priority,
	)
	var i SrvRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Target,
		&i.Port,
		&i.Weight,
		&i.Priority,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsCreateTXT = `-- name: RecordsCreateTXT :one
INSERT INTO txt_records (domain_id, value)
VALUES ($1, $2)
ON CONFLICT (domain_id, value)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, value, created_at, updated_at
`

type RecordsCreateTXTParams struct {
	DomainID pgtype.Int4 `json:"domain_id"`
	Value    string      `json:"value"`
}

// TXT Records
func (q *Queries) RecordsCreateTXT(ctx context.Context, arg RecordsCreateTXTParams) (TxtRecords, error) {
	row := q.db.QueryRow(ctx, recordsCreateTXT, arg.DomainID, arg.Value)
	var i TxtRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Value,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetAAAAByDomainID = `-- name: RecordsGetAAAAByDomainID :one
SELECT id, uid, domain_id, ipv6_address, created_at, updated_at
FROM aaaa_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetAAAAByDomainID(ctx context.Context, domainID pgtype.Int4) (AaaaRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetAAAAByDomainID, domainID)
	var i AaaaRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Ipv6Address,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetAByDomainID = `-- name: RecordsGetAByDomainID :one
SELECT id, uid, domain_id, ipv4_address, created_at, updated_at
FROM a_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetAByDomainID(ctx context.Context, domainID pgtype.Int4) (ARecords, error) {
	row := q.db.QueryRow(ctx, recordsGetAByDomainID, domainID)
	var i ARecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Ipv4Address,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetAllByDomainID = `-- name: RecordsGetAllByDomainID :many
SELECT d.name             AS domain_name,
       a.ipv4_address,
       aaaa.ipv6_address,
       mx.preference      AS mx_pref,
       mx.target          AS mx_target,
       txt.value          AS txt_value,
       ns.nameserver,
       cname.target       AS cname_target,
       ptr.target         AS ptr_target,
       srv.target         AS srv_target,
       srv.port           AS srv_port,
       srv.priority       AS srv_priority,
       soa.nameserver     AS soa_nameserver,
       soa.serial         AS soa_serial,
       caa.flags          AS caa_flags,
       caa.tag            AS caa_tag,
       caa.value          AS caa_value,
       dnskey.public_key  AS dnskey_public_key,
       dnskey.flags       AS dnskey_flags,
       dnskey.protocol    AS dnskey_protocol,
       dnskey.algorithm   AS dnskey_algorithm,
       ds.key_tag         AS ds_keytag,
       ds.algorithm       AS ds_algorithm,
       ds.digest_type     AS ds_digest_type,
       ds.digest          AS ds_digest,
       rrsig.type_covered AS rrsig_type_covered,
       rrsig.algorithm    AS rrsig_algorithm,
       rrsig.labels       AS rrsig_labels,
       rrsig.original_ttl AS rrsig_original_ttl,
       rrsig.expiration   AS rrsig_expiration,
       rrsig.inception    AS rrsig_inception,
       rrsig.key_tag      AS rrsig_keytag,
       rrsig.signer_name  AS rrsig_signer_name,
       rrsig.signature    AS rrsig_signature
FROM domains d
         LEFT JOIN a_records a ON d.id = a.domain_id
         LEFT JOIN aaaa_records aaaa ON d.id = aaaa.domain_id
         LEFT JOIN mx_records mx ON d.id = mx.domain_id
         LEFT JOIN txt_records txt ON d.id = txt.domain_id
         LEFT JOIN ns_records ns ON d.id = ns.domain_id
         LEFT JOIN cname_records cname ON d.id = cname.domain_id
         LEFT JOIN ptr_records ptr ON d.id = ptr.domain_id
         LEFT JOIN srv_records srv ON d.id = srv.domain_id
         LEFT JOIN soa_records soa ON d.id = soa.domain_id
         LEFT JOIN caa_records caa ON d.id = caa.domain_id
         LEFT JOIN dnskey_records dnskey ON d.id = dnskey.domain_id
         LEFT JOIN ds_records ds ON d.id = ds.domain_id
         LEFT JOIN rrsig_records rrsig ON d.id = rrsig.domain_id
WHERE d.id = $1
ORDER BY d.name
LIMIT $2 OFFSET $3
`

type RecordsGetAllByDomainIDParams struct {
	ID     int32 `json:"id"`
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

type RecordsGetAllByDomainIDRow struct {
	DomainName       string      `json:"domain_name"`
	Ipv4Address      pgtype.Text `json:"ipv4_address"`
	Ipv6Address      pgtype.Text `json:"ipv6_address"`
	MxPref           pgtype.Int4 `json:"mx_pref"`
	MxTarget         pgtype.Text `json:"mx_target"`
	TxtValue         pgtype.Text `json:"txt_value"`
	Nameserver       pgtype.Text `json:"nameserver"`
	CnameTarget      pgtype.Text `json:"cname_target"`
	PtrTarget        pgtype.Text `json:"ptr_target"`
	SrvTarget        pgtype.Text `json:"srv_target"`
	SrvPort          pgtype.Int4 `json:"srv_port"`
	SrvPriority      pgtype.Int4 `json:"srv_priority"`
	SoaNameserver    pgtype.Text `json:"soa_nameserver"`
	SoaSerial        pgtype.Int8 `json:"soa_serial"`
	CaaFlags         pgtype.Int4 `json:"caa_flags"`
	CaaTag           pgtype.Text `json:"caa_tag"`
	CaaValue         pgtype.Text `json:"caa_value"`
	DnskeyPublicKey  pgtype.Text `json:"dnskey_public_key"`
	DnskeyFlags      pgtype.Int4 `json:"dnskey_flags"`
	DnskeyProtocol   pgtype.Int4 `json:"dnskey_protocol"`
	DnskeyAlgorithm  pgtype.Int4 `json:"dnskey_algorithm"`
	DsKeytag         pgtype.Int4 `json:"ds_keytag"`
	DsAlgorithm      pgtype.Int4 `json:"ds_algorithm"`
	DsDigestType     pgtype.Int4 `json:"ds_digest_type"`
	DsDigest         pgtype.Text `json:"ds_digest"`
	RrsigTypeCovered pgtype.Int4 `json:"rrsig_type_covered"`
	RrsigAlgorithm   pgtype.Int4 `json:"rrsig_algorithm"`
	RrsigLabels      pgtype.Int4 `json:"rrsig_labels"`
	RrsigOriginalTtl pgtype.Int4 `json:"rrsig_original_ttl"`
	RrsigExpiration  pgtype.Int4 `json:"rrsig_expiration"`
	RrsigInception   pgtype.Int4 `json:"rrsig_inception"`
	RrsigKeytag      pgtype.Int4 `json:"rrsig_keytag"`
	RrsigSignerName  pgtype.Text `json:"rrsig_signer_name"`
	RrsigSignature   pgtype.Text `json:"rrsig_signature"`
}

// todo: develop only; reconsider need for this
func (q *Queries) RecordsGetAllByDomainID(ctx context.Context, arg RecordsGetAllByDomainIDParams) ([]RecordsGetAllByDomainIDRow, error) {
	rows, err := q.db.Query(ctx, recordsGetAllByDomainID, arg.ID, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []RecordsGetAllByDomainIDRow{}
	for rows.Next() {
		var i RecordsGetAllByDomainIDRow
		if err := rows.Scan(
			&i.DomainName,
			&i.Ipv4Address,
			&i.Ipv6Address,
			&i.MxPref,
			&i.MxTarget,
			&i.TxtValue,
			&i.Nameserver,
			&i.CnameTarget,
			&i.PtrTarget,
			&i.SrvTarget,
			&i.SrvPort,
			&i.SrvPriority,
			&i.SoaNameserver,
			&i.SoaSerial,
			&i.CaaFlags,
			&i.CaaTag,
			&i.CaaValue,
			&i.DnskeyPublicKey,
			&i.DnskeyFlags,
			&i.DnskeyProtocol,
			&i.DnskeyAlgorithm,
			&i.DsKeytag,
			&i.DsAlgorithm,
			&i.DsDigestType,
			&i.DsDigest,
			&i.RrsigTypeCovered,
			&i.RrsigAlgorithm,
			&i.RrsigLabels,
			&i.RrsigOriginalTtl,
			&i.RrsigExpiration,
			&i.RrsigInception,
			&i.RrsigKeytag,
			&i.RrsigSignerName,
			&i.RrsigSignature,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const recordsGetCAAByDomainID = `-- name: RecordsGetCAAByDomainID :one
SELECT id,
       uid,
       domain_id,
       flags,
       tag,
       value,
       created_at,
       updated_at
FROM caa_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetCAAByDomainID(ctx context.Context, domainID pgtype.Int4) (CaaRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetCAAByDomainID, domainID)
	var i CaaRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Flags,
		&i.Tag,
		&i.Value,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetCNAMEByDomainID = `-- name: RecordsGetCNAMEByDomainID :one
SELECT id, uid, domain_id, target, created_at, updated_at
FROM cname_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetCNAMEByDomainID(ctx context.Context, domainID pgtype.Int4) (CnameRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetCNAMEByDomainID, domainID)
	var i CnameRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Target,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetDNSKEYByDomainID = `-- name: RecordsGetDNSKEYByDomainID :one
SELECT id,
       uid,
       domain_id,
       public_key,
       flags,
       protocol,
       algorithm,
       created_at,
       updated_at
FROM dnskey_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetDNSKEYByDomainID(ctx context.Context, domainID pgtype.Int4) (DnskeyRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetDNSKEYByDomainID, domainID)
	var i DnskeyRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.PublicKey,
		&i.Flags,
		&i.Protocol,
		&i.Algorithm,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetDNSSECByDomainID = `-- name: RecordsGetDNSSECByDomainID :many
SELECT d.name           as domain_name,
       dnskey.public_key,
       dnskey.flags,
       dnskey.algorithm as dnskey_algorithm,
       ds.key_tag,
       ds.digest_type,
       ds.digest,
       rrsig.type_covered,
       rrsig.expiration,
       rrsig.signer_name
FROM domains d
         LEFT JOIN dnskey_records dnskey ON d.id = dnskey.domain_id
         LEFT JOIN ds_records ds ON d.id = ds.domain_id
         LEFT JOIN rrsig_records rrsig ON d.id = rrsig.domain_id
WHERE d.id = $1
`

type RecordsGetDNSSECByDomainIDRow struct {
	DomainName      string      `json:"domain_name"`
	PublicKey       pgtype.Text `json:"public_key"`
	Flags           pgtype.Int4 `json:"flags"`
	DnskeyAlgorithm pgtype.Int4 `json:"dnskey_algorithm"`
	KeyTag          pgtype.Int4 `json:"key_tag"`
	DigestType      pgtype.Int4 `json:"digest_type"`
	Digest          pgtype.Text `json:"digest"`
	TypeCovered     pgtype.Int4 `json:"type_covered"`
	Expiration      pgtype.Int4 `json:"expiration"`
	SignerName      pgtype.Text `json:"signer_name"`
}

// Get all DNSSEC records for a domain
func (q *Queries) RecordsGetDNSSECByDomainID(ctx context.Context, id int32) ([]RecordsGetDNSSECByDomainIDRow, error) {
	rows, err := q.db.Query(ctx, recordsGetDNSSECByDomainID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []RecordsGetDNSSECByDomainIDRow{}
	for rows.Next() {
		var i RecordsGetDNSSECByDomainIDRow
		if err := rows.Scan(
			&i.DomainName,
			&i.PublicKey,
			&i.Flags,
			&i.DnskeyAlgorithm,
			&i.KeyTag,
			&i.DigestType,
			&i.Digest,
			&i.TypeCovered,
			&i.Expiration,
			&i.SignerName,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const recordsGetDSByDomainID = `-- name: RecordsGetDSByDomainID :one
SELECT id,
       uid,
       domain_id,
       key_tag,
       algorithm,
       digest_type,
       digest,
       created_at,
       updated_at
FROM ds_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetDSByDomainID(ctx context.Context, domainID pgtype.Int4) (DsRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetDSByDomainID, domainID)
	var i DsRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.KeyTag,
		&i.Algorithm,
		&i.DigestType,
		&i.Digest,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetMXByDomainID = `-- name: RecordsGetMXByDomainID :one
SELECT id, uid, domain_id, preference, target, created_at, updated_at
FROM mx_records
WHERE domain_id = $1
ORDER BY preference
`

func (q *Queries) RecordsGetMXByDomainID(ctx context.Context, domainID pgtype.Int4) (MxRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetMXByDomainID, domainID)
	var i MxRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Preference,
		&i.Target,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetNSByDomainID = `-- name: RecordsGetNSByDomainID :one
SELECT id, uid, domain_id, nameserver, created_at, updated_at
FROM ns_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetNSByDomainID(ctx context.Context, domainID pgtype.Int4) (NsRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetNSByDomainID, domainID)
	var i NsRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Nameserver,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetPTRByDomainID = `-- name: RecordsGetPTRByDomainID :one
SELECT id, uid, domain_id, target, created_at, updated_at
FROM ptr_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetPTRByDomainID(ctx context.Context, domainID pgtype.Int4) (PtrRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetPTRByDomainID, domainID)
	var i PtrRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Target,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetRRSIGByDomainID = `-- name: RecordsGetRRSIGByDomainID :one
SELECT id,
       uid,
       domain_id,
       type_covered,
       algorithm,
       labels,
       original_ttl,
       expiration,
       inception,
       key_tag,
       signer_name,
       signature,
       created_at,
       updated_at
FROM rrsig_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetRRSIGByDomainID(ctx context.Context, domainID pgtype.Int4) (RrsigRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetRRSIGByDomainID, domainID)
	var i RrsigRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.TypeCovered,
		&i.Algorithm,
		&i.Labels,
		&i.OriginalTtl,
		&i.Expiration,
		&i.Inception,
		&i.KeyTag,
		&i.SignerName,
		&i.Signature,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetSOAByDomainID = `-- name: RecordsGetSOAByDomainID :one
SELECT id,
       uid,
       domain_id,
       nameserver,
       email,
       serial,
       refresh,
       retry,
       expire,
       minimum_ttl,
       created_at,
       updated_at
FROM soa_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetSOAByDomainID(ctx context.Context, domainID pgtype.Int4) (SoaRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetSOAByDomainID, domainID)
	var i SoaRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Nameserver,
		&i.Email,
		&i.Serial,
		&i.Refresh,
		&i.Retry,
		&i.Expire,
		&i.MinimumTtl,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetSRVByDomainID = `-- name: RecordsGetSRVByDomainID :one
SELECT id,
       uid,
       domain_id,
       target,
       port,
       weight,
       priority,
       created_at,
       updated_at
FROM srv_records
WHERE domain_id = $1
ORDER BY priority, weight
`

func (q *Queries) RecordsGetSRVByDomainID(ctx context.Context, domainID pgtype.Int4) (SrvRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetSRVByDomainID, domainID)
	var i SrvRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Target,
		&i.Port,
		&i.Weight,
		&i.Priority,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const recordsGetTXTByDomainID = `-- name: RecordsGetTXTByDomainID :one
SELECT id, uid, domain_id, value, created_at, updated_at
FROM txt_records
WHERE domain_id = $1
`

func (q *Queries) RecordsGetTXTByDomainID(ctx context.Context, domainID pgtype.Int4) (TxtRecords, error) {
	row := q.db.QueryRow(ctx, recordsGetTXTByDomainID, domainID)
	var i TxtRecords
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.DomainID,
		&i.Value,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
