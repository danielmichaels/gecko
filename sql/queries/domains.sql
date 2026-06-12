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

-- name: DomainsInsert :one
-- Insert-only create for the POST path. Unlike DomainsCreate (an upsert used by
-- enumeration), a duplicate (tenant_id, name) raises a unique-violation the
-- handler maps to 409 — so a duplicate POST never silently becomes a rescan.
INSERT INTO domains (tenant_id, name, domain_type, source, status)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, uid, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsGetByID :one
SELECT id,
       uid,
       tenant_id,
       name,
       domain_type,
       source,
       status,
       scan_frequency,
       next_scan_at,
       last_scanned_at,
       created_at,
       updated_at
FROM domains
WHERE uid = $1
  AND tenant_id = $2;

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
-- name: DomainsGetByIdentifier :one
-- Read a domain by ID, UID, or name and tenant ID (no auth)
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
  AND (id = $2 OR uid = $3 OR name = $4)
LIMIT 1;

-- name: DomainsUpdateByID :one
-- Update a domain's status (no auth)
UPDATE domains
SET status      = $2,
    domain_type = $3,
    source      = $4
WHERE uid = $1
  AND tenant_id = $5
RETURNING id, uid, tenant_id, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsUpdateByIDTypeSource :one
-- Update a domain's type and source (no auth)
UPDATE domains
SET domain_type = $2,
    source      = $3
WHERE uid = $1
  AND tenant_id = $4
RETURNING id, uid, tenant_id, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsDeleteByID :one
-- Delete a domain (no auth)
DELETE
FROM domains
WHERE uid = $1
  AND tenant_id = $2
RETURNING id, uid, tenant_id, name, domain_type, source, status, created_at, updated_at;

-- name: DomainsIDsByTenantID :many
-- All domain IDs owned by a tenant. Used by the per-tenant stats refresh to
-- drive the index-driven record/finding aggregates; returns no rows when the
-- tenant has no domains (the caller then caches zeros).
SELECT id
FROM domains
WHERE tenant_id = $1;

-- name: DomainsListByTenantID :many
-- List all domains for a tenant with pagination (no auth)
SELECT id,
       uid,
       tenant_id,
       name,
       domain_type,
       source,
       status,
       last_scanned_at,
       next_scan_at,
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
       last_scanned_at,
       next_scan_at,
       created_at,
       updated_at,
       count(*) OVER () AS total_count
FROM domains
WHERE tenant_id = $1
  AND name ILIKE $2
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: DomainsDeleteCount :one
WITH RECURSIVE domain_tree AS (
    -- Base case: the domain we're deleting
    SELECT d.id, d.uid, d.name
    FROM domains d
    WHERE d.uid = $1
      AND d.tenant_id = $2

    UNION ALL

    -- Recursive case: all child domains
    SELECT d.id, d.uid, d.name
    FROM domains d
             JOIN domain_tree dt ON d.parent_domain_id = dt.id)
SELECT COUNT(*)
FROM domain_tree;

-- name: DomainsListDueForScan :many
-- The scheduler's hot query: active domains whose scheduling cursor has come due,
-- oldest-due first, capped at @batch_limit so a burst of simultaneously-due
-- domains can't thunder-herd queue_scanner (the rest stay due for the next tick).
-- Rides the partial index idx_domains_next_scan_at. Returns the effective
-- frequency (own override ?? tenant default) so the caller sets a matching recency
-- window. 'off' domains have a NULL cursor and are excluded by the index.
SELECT d.id,
       d.uid,
       d.tenant_id,
       d.name,
       d.status,
       COALESCE(d.scan_frequency, ts.default_scan_frequency, 'daily')::scan_frequency AS effective_frequency
FROM domains d
         LEFT JOIN tenant_settings ts ON ts.tenant_id = d.tenant_id
WHERE d.status = 'active'
  AND d.next_scan_at IS NOT NULL
  AND d.next_scan_at <= now()
ORDER BY d.next_scan_at ASC
LIMIT sqlc.arg(batch_limit);

-- name: DomainsGetScanFrequencies :one
-- Resolve a domain's scheduling inputs in one read: its own override (NULL =
-- inherit) and its tenant's default. EnqueueDomainScan's chokepoint uses this to
-- compute the effective frequency. Falls back to 'daily' when the tenant has no
-- settings row yet (brand-new tenant before its first settings write).
SELECT d.scan_frequency,
       COALESCE(ts.default_scan_frequency, 'daily')::scan_frequency AS default_scan_frequency
FROM domains d
         LEFT JOIN tenant_settings ts ON ts.tenant_id = d.tenant_id
WHERE d.id = sqlc.arg(domain_id);

-- name: DomainsMarkScanned :exec
-- The single chokepoint stamp, called from EnqueueDomainScan after a scan row is
-- created — so it fires on EVERY trigger (manual, scheduled, discovered). Stamps
-- the real last-scan time and advances the scheduling cursor by the effective
-- interval with ±10% jitter to de-herd a same-tick batch. @is_off true => the
-- cursor is cleared (NULL) so the domain falls out of the schedule.
UPDATE domains
SET last_scanned_at = now(),
    next_scan_at    = CASE
                          WHEN sqlc.arg(is_off)::boolean THEN NULL
                          ELSE now()
                              + make_interval(secs => sqlc.arg(base_secs)::double precision)
                              + make_interval(secs => sqlc.arg(base_secs)::double precision * random() * 0.10)
        END
WHERE id = sqlc.arg(domain_id);

-- name: DomainsSetScanFrequency :one
-- Set a domain's per-domain override (NULL = inherit the tenant default) and
-- recompute its scheduling cursor from the supplied effective interval (±10%
-- jitter). @is_off true => cursor NULL (paused). Tenant-scoped by uid + tenant_id.
UPDATE domains
SET scan_frequency = sqlc.narg(scan_frequency),
    next_scan_at   = CASE
                         WHEN sqlc.arg(is_off)::boolean THEN NULL
                         ELSE now()
                             + make_interval(secs => sqlc.arg(base_secs)::double precision)
                             + make_interval(secs => sqlc.arg(base_secs)::double precision * random() * 0.10)
        END
WHERE uid = sqlc.arg(uid)
  AND tenant_id = sqlc.arg(tenant_id)
RETURNING id, uid, tenant_id, name, domain_type, source, status, scan_frequency,
    next_scan_at, last_scanned_at, created_at, updated_at;

-- name: DomainsRecomputeNextScanByTenantDefault :exec
-- Bulk-recompute next_scan_at for a tenant's inheriting domains (no override)
-- after its default changes. Overridden domains (scan_frequency NOT NULL) are
-- untouched; inactive domains are skipped (they re-enter via the due path on
-- reactivation). Bounded to one tenant + active rows; re-jitters per row so a bulk
-- default change can't herd. @is_off true => those domains are paused (cursor NULL).
UPDATE domains
SET next_scan_at = CASE
                       WHEN sqlc.arg(is_off)::boolean THEN NULL
                       ELSE now()
                           + make_interval(secs => sqlc.arg(base_secs)::double precision)
                           + make_interval(secs => sqlc.arg(base_secs)::double precision * random() * 0.10)
    END
WHERE tenant_id = sqlc.arg(tenant_id)
  AND scan_frequency IS NULL
  AND status = 'active';