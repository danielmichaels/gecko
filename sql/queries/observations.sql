-- name: ScansCreate :one
-- Create a scan correlation row. Scans group every observation emitted during a
-- single domain scan so the timeline can diff scan N vs N+1.
INSERT INTO scans (tenant_id, domain_id, domain_uid, domain_name, parent_scan_id, source)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, uid, tenant_id, domain_id, domain_uid, domain_name, parent_scan_id, source, started_at;

-- name: AcquireDomainScanLock :exec
-- Transaction-scoped advisory lock keyed on domain_id. Serializes concurrent
-- scan enqueues for the same domain so the recency-check-then-enqueue is atomic
-- (auto-released at commit/rollback; no phantom-row gap like FOR UPDATE).
SELECT pg_advisory_xact_lock($1::bigint);

-- name: ScansGetRecentByTenantDomainName :one
-- Most recent scan for a (tenant, domain name). Backs the recency guard that
-- dedupes discovered scans. Keyed on (tenant_id, domain_name), not domain_id,
-- so it survives a domain delete/re-add.
SELECT id, uid, tenant_id, domain_id, domain_uid, domain_name, parent_scan_id, source, started_at
FROM scans
WHERE tenant_id = $1
  AND domain_name = $2
ORDER BY started_at DESC
LIMIT 1;

-- name: ScansListByParent :many
-- Child scans of an apex scan (lineage). Lets the timeline group discovered
-- child scans under the scan that found them.
SELECT id, uid, tenant_id, domain_id, domain_uid, domain_name, parent_scan_id, source, started_at
FROM scans
WHERE parent_scan_id = $1
ORDER BY started_at DESC;

-- name: ScansListByTenantDomainName :many
-- All scans for a (tenant, domain name), newest first.
SELECT id, uid, tenant_id, domain_id, domain_uid, domain_name, parent_scan_id, source, started_at
FROM scans
WHERE tenant_id = $1
  AND domain_name = $2
ORDER BY started_at DESC;

-- name: ObservationsCreate :one
-- Append one change to the observation log.
INSERT INTO domain_observations (tenant_id, domain_id, domain_uid, domain_name, scan_id, entity_type, entity_key,
                                 change_type, payload)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, tenant_id, domain_id, domain_uid, domain_name, scan_id, entity_type, entity_key, change_type, payload, observed_at;

-- name: ObservationsListByTenantDomainName :many
-- Timeline for a (tenant, domain name). Keyed on (tenant_id, domain_name) so a
-- re-added domain shows its prior timeline and a deleted domain stays reachable.
SELECT id, tenant_id, domain_id, domain_uid, domain_name, scan_id, entity_type, entity_key, change_type, payload, observed_at
FROM domain_observations
WHERE tenant_id = $1
  AND domain_name = $2
ORDER BY observed_at DESC;

-- name: ObservationsListByScan :many
-- All observations emitted during a single scan (scan-diff feature).
SELECT id, tenant_id, domain_id, domain_uid, domain_name, scan_id, entity_type, entity_key, change_type, payload, observed_at
FROM domain_observations
WHERE scan_id = $1
ORDER BY entity_type, entity_key;
