-- name: DomainsGetAllRecordsByTenantID :many
-- Get domains with all their DNS records
-- todo: add pagination
SELECT d.name,
       a.ipv4_address,
       aaaa.ipv6_address,
       mx.preference as mx_pref,
       mx.target     as mx_target,
       txt.value     as txt_record,
       ptr.target    as ptr_target,
       cname.target  as cname_target,
       ns.nameserver
FROM domains d
         LEFT JOIN a_records a ON d.id = a.domain_id
         LEFT JOIN aaaa_records aaaa ON d.id = aaaa.domain_id
         LEFT JOIN mx_records mx ON d.id = mx.domain_id
         LEFT JOIN txt_records txt ON d.id = txt.domain_id
         LEFT JOIN ptr_records ptr ON d.id = ptr.domain_id
         LEFT JOIN cname_records cname ON d.id = cname.domain_id
         LEFT JOIN ns_records ns ON d.id = ns.domain_id
WHERE d.tenant_id = $1;

-- name: DomainsCreate :one
-- Create a new domain (no auth)
INSERT INTO domains (tenant_id, name, domain_type, source, status)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, name)
    DO UPDATE SET updated_at = NOW()
RETURNING id, uid, name, domain_type, source, status;

-- name: DomainsReadByID :one
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
WHERE id = $1;

-- name: DomainsReadByName :one
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
SET status = $2
WHERE id = $1
RETURNING id, uid, tenant_id, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsUpdateByIDTypeSource :one
-- Update a domain's type and source (no auth)
UPDATE domains
SET domain_type = $2,
    source      = $3
WHERE id = $1
RETURNING id, uid, tenant_id, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsDeleteByID :one
-- Delete a domain (no auth)
DELETE
FROM domains
WHERE id = $1
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
       updated_at
FROM domains
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: DomainsListAll :many
-- List all domains (no auth, for development/debugging only - avoid in production)
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
