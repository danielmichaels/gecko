-- name: RecordsCreateA :one
-- A Records
INSERT INTO a_records (domain_id, ipv4_address)
VALUES ($1, $2)
ON CONFLICT (domain_id, ipv4_address)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, ipv4_address, created_at, updated_at;

-- name: RecordsGetAByDomainID :many
SELECT id, uid, domain_id, ipv4_address, created_at, updated_at
FROM a_records
WHERE domain_id = $1;

-- name: RecordsCreateAAAA :one
-- AAAA Records
INSERT INTO aaaa_records (domain_id, ipv6_address)
VALUES ($1, $2)
ON CONFLICT (domain_id, ipv6_address)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, ipv6_address, created_at, updated_at;

-- name: RecordsGetAAAAByDomainID :many
SELECT id, uid, domain_id, ipv6_address, created_at, updated_at
FROM aaaa_records
WHERE domain_id = $1;

-- name: RecordsCreateMX :one
-- MX Records
INSERT INTO mx_records (domain_id, preference, target)
VALUES ($1, $2, $3)
ON CONFLICT (domain_id, preference, target)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, preference, target, created_at, updated_at;


-- name: RecordsGetMXByDomainID :many
SELECT id, uid, domain_id, preference, target, created_at, updated_at
FROM mx_records
WHERE domain_id = $1
ORDER BY preference;

-- name: RecordsCreateTXT :one
-- TXT Records
INSERT INTO txt_records (domain_id, value)
VALUES ($1, $2)
ON CONFLICT (domain_id, value)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, value, created_at, updated_at;;

-- name: RecordsGetTXTByDomainID :many
SELECT id, uid, domain_id, value, created_at, updated_at
FROM txt_records
WHERE domain_id = $1;

-- name: RecordsCreateNS :one
-- NS Records
INSERT INTO ns_records (domain_id, nameserver)
VALUES ($1, $2)
ON CONFLICT (domain_id, nameserver)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, nameserver, created_at, updated_at;

-- name: RecordsGetNSByDomainID :many
SELECT id, uid, domain_id, nameserver, created_at, updated_at
FROM ns_records
WHERE domain_id = $1;

-- name: RecordsCreateCNAME :one
-- CNAME Records
INSERT INTO cname_records (domain_id, target)
VALUES ($1, $2)
ON CONFLICT (domain_id, target)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, target, created_at, updated_at;

-- name: RecordsGetCNAMEByDomainID :many
SELECT id, uid, domain_id, target, created_at, updated_at
FROM cname_records
WHERE domain_id = $1;

-- name: RecordsCreatePTR :one
-- PTR Records
INSERT INTO ptr_records (domain_id, target)
VALUES ($1, $2)
ON CONFLICT (domain_id, target)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, domain_id, target, created_at, updated_at;

-- name: RecordsGetPTRByDomainID :many
SELECT id, uid, domain_id, target, created_at, updated_at
FROM ptr_records
WHERE domain_id = $1;

-- name: RecordsCreateSRV :one
INSERT INTO srv_records (domain_id, target, port, weight, priority)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (domain_id, target, port, priority)
    DO UPDATE SET weight     = $4,
                  updated_at = NOW()
RETURNING id, uid, domain_id, target, port, weight, priority, created_at, updated_at;


-- name: RecordsGetSRVByDomainID :many
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
ORDER BY priority, weight;

-- name: RecordsCreateSOA :one
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
RETURNING id, uid, domain_id, nameserver, email, serial, refresh, retry, expire, minimum_ttl, created_at, updated_at;

-- name: RecordsGetSOAByDomainID :many
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
WHERE domain_id = $1;

-- name: RecordsCreateDNSKEY :one
INSERT INTO dnskey_records (domain_id, public_key, flags, protocol, algorithm)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (domain_id, public_key)
    DO UPDATE SET flags      = $3,
                  protocol   = $4,
                  algorithm  = $5,
                  updated_at = NOW()
RETURNING id, uid, domain_id, public_key, flags, protocol, algorithm, created_at, updated_at;

-- name: RecordsGetDNSKEYByDomainID :many
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
WHERE domain_id = $1;

-- name: RecordsCreateDS :one
-- DS Records
INSERT INTO ds_records (domain_id, key_tag, algorithm, digest_type, digest)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (domain_id, digest)
    DO UPDATE SET key_tag     = $2,
                  algorithm   = $3,
                  digest_type = $4,
                  updated_at  = NOW()
RETURNING id, uid, domain_id, key_tag, algorithm, digest_type, digest, created_at, updated_at;

-- name: RecordsGetDSByDomainID :many
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
WHERE domain_id = $1;

-- name: RecordsCreateRRSIG :one
-- RRSIG Records
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
RETURNING id, uid, domain_id, type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer_name, signature, created_at, updated_at;

-- name: RecordsGetRRSIGByDomainID :many
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
WHERE domain_id = $1;

-- name: RecordsGetDNSSECByDomainID :many
-- Get all DNSSEC records for a domain
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
WHERE d.id = $1;

-- name: RecordsGetAllByDomainID :many
-- todo: develop only; reconsider need for this
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
LIMIT $2 OFFSET $3;


-- name: RecordsCreateCAA :one
-- CAA Records
INSERT INTO caa_records (domain_id, flags, tag, value)
VALUES ($1, $2, $3, $4)
ON CONFLICT (domain_id, tag, value)
    DO UPDATE SET flags      = $2,
                  updated_at = NOW()
RETURNING id, uid, domain_id, flags, tag, value, created_at, updated_at;

-- name: RecordsGetCAAByDomainID :many
SELECT id,
       uid,
       domain_id,
       flags,
       tag,
       value,
       created_at,
       updated_at
FROM caa_records
WHERE domain_id = $1;
