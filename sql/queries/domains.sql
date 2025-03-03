-- name: DomainsGetAllRecordsByTenantID :many
-- Get domains with all their DNS records
-- todo: develop only; reconsider need for this
SELECT d.name,
       a.ipv4_address,
       aaaa.ipv6_address,
       mx.preference      AS mx_pref,
       mx.target          AS mx_target,
       txt.value          AS txt_record,
       ptr.target         AS ptr_target,
       cname.target       AS cname_target,
       ns.nameserver,
       soa.nameserver     AS soa_nameserver,
       soa.email          AS soa_email,
       soa.serial         AS soa_serial,
       soa.refresh        AS soa_refresh,
       soa.retry          AS soa_retry,
       soa.expire         AS soa_expire,
       soa.minimum_ttl    AS soa_minimum_ttl,
       srv.target         AS srv_target,
       srv.port           AS srv_port,
       srv.weight         AS srv_weight,
       srv.priority       AS srv_priority,
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
         LEFT JOIN ptr_records ptr ON d.id = ptr.domain_id
         LEFT JOIN cname_records cname ON d.id = cname.domain_id
         LEFT JOIN ns_records ns ON d.id = ns.domain_id
         LEFT JOIN soa_records soa ON d.id = soa.domain_id
         LEFT JOIN srv_records srv ON d.id = srv.domain_id
         LEFT JOIN caa_records caa ON d.id = caa.domain_id
         LEFT JOIN dnskey_records dnskey ON d.id = dnskey.domain_id
         LEFT JOIN ds_records ds ON d.id = ds.domain_id
         LEFT JOIN rrsig_records rrsig ON d.id = rrsig.domain_id
WHERE d.tenant_id = $1
ORDER BY d.name ASC
LIMIT $2 OFFSET $3;


-- name: DomainsCreate :one
-- Create a new domain (no auth)
INSERT INTO domains (tenant_id, name, domain_type, source, status)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, name)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsGetByID :one
SELECT id,
       uid,
       tenant_id,
       name,
       domain_type,
       source,
       status,
       created_at,
       updated_at
FROM domains
WHERE uid = $1;

-- name: DomainsGetByName :one
-- Read a domain by name and tenant ID (no auth)
SELECT id,
       uid,
       tenant_id,
       name,
       domain_type,
       source,
       status,
       created_at,
       updated_at
FROM domains
WHERE tenant_id = $1
  AND name = $2;

-- name: DomainsUpdateByID :one
-- Update a domain's status (no auth)
UPDATE domains
SET status      = $2,
    domain_type = $3,
    source      = $4
WHERE uid = $1
RETURNING id, uid, tenant_id, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsUpdateByIDTypeSource :one
-- Update a domain's type and source (no auth)
UPDATE domains
SET domain_type = $2,
    source      = $3
WHERE uid = $1
RETURNING id, uid, tenant_id, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsDeleteByID :one
-- Delete a domain (no auth)
DELETE
FROM domains
WHERE uid = $1
RETURNING id, uid, tenant_id, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsListByTenantID :many
-- List all domains for a tenant with pagination (no auth)
SELECT id,
       uid,
       tenant_id,
       name,
       domain_type,
       source,
       status,
       created_at,
       updated_at,
       count(*) OVER () AS total_count
FROM domains
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: DomainsSearchByName :many
SELECT id,
       uid,
       tenant_id,
       name,
       domain_type,
       source,
       status,
       created_at,
       updated_at,
       count(*) OVER () AS total_count
FROM domains
WHERE tenant_id = $1
  AND name ILIKE $2
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: DomainsListAll :many
-- fixme: List all domains (no auth, for development/debugging only - avoid in production)
SELECT id,
       uid,
       tenant_id,
       name,
       domain_type,
       source,
       status,
       created_at,
       updated_at
FROM domains
ORDER BY created_at DESC;

-- name: DomainsDeleteCount :one
WITH RECURSIVE domain_tree AS (
    -- Base case: the domain we're deleting
    SELECT d.id, d.uid, d.name
    FROM domains d
    WHERE d.uid = $1

    UNION ALL

    -- Recursive case: all child domains
    SELECT d.id, d.uid, d.name
    FROM domains d
             JOIN domain_tree dt ON d.parent_domain_id = dt.id)
SELECT COUNT(*)
FROM domain_tree;