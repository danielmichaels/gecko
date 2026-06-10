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
ORDER BY started_at DESC, id DESC;

-- name: ScansListByTenantDomainName :many
-- All scans for a (tenant, domain name), newest first.
SELECT id, uid, tenant_id, domain_id, domain_uid, domain_name, parent_scan_id, source, started_at
FROM scans
WHERE tenant_id = $1
  AND domain_name = $2
ORDER BY started_at DESC, id DESC;

-- name: ScansListByTenant :many
-- Tenant-wide reverse-chronological scan feed with per-scan change aggregates.
-- Observation aggregation is bounded to the windowed page (target_scans, capped
-- by @row_limit) so it never full-scans a growing domain_observations: the
-- change_counts CTE keys on scan_id from target_scans and rides idx_obs_scan.
-- Clean scans (no observations) survive via LEFT JOIN per_scan -> all-zero counts
-- + '[]' breakdown. Baseline scans (parent_scan_id IS NULL) yield a NULL
-- parent_scan_uid. @since is nullable: NULL means all-time.
WITH target_scans AS (
    SELECT s.id, s.uid, s.domain_uid, s.domain_name, s.source,
           s.started_at, s.parent_scan_id
    FROM scans s
    WHERE s.tenant_id = @tenant_id
      AND (sqlc.narg(since)::timestamptz IS NULL
           OR s.started_at >= sqlc.narg(since))
    ORDER BY s.started_at DESC, s.id DESC
    LIMIT sqlc.arg(row_limit)
),
change_counts AS (
    SELECT o.scan_id, o.entity_type, o.change_type, count(*) AS n
    FROM domain_observations o
    WHERE o.scan_id IN (SELECT id FROM target_scans)
    GROUP BY o.scan_id, o.entity_type, o.change_type
),
per_scan AS (
    SELECT scan_id,
           COALESCE(sum(n) FILTER (WHERE change_type = 'created'), 0) AS created,
           COALESCE(sum(n) FILTER (WHERE change_type = 'updated'), 0) AS updated,
           COALESCE(sum(n) FILTER (WHERE change_type = 'deleted'), 0) AS deleted,
           jsonb_agg(jsonb_build_object(
               'entity_type', entity_type,
               'change_type', change_type,
               'count', n) ORDER BY entity_type, change_type) AS breakdown
    FROM change_counts
    GROUP BY scan_id
)
SELECT t.uid                          AS scan_uid,
       t.domain_uid,
       t.domain_name,
       t.source,
       t.started_at,
       p.uid                          AS parent_scan_uid,
       COALESCE(ps.created, 0)::int   AS created_count,
       COALESCE(ps.updated, 0)::int   AS updated_count,
       COALESCE(ps.deleted, 0)::int   AS deleted_count,
       COALESCE(ps.breakdown, '[]'::jsonb) AS breakdown
FROM target_scans t
         LEFT JOIN scans p ON p.id = t.parent_scan_id
         LEFT JOIN per_scan ps ON ps.scan_id = t.id
ORDER BY t.started_at DESC, t.id DESC;

-- name: ScansGetByTenantUID :one
-- Single scan by (tenant_id, uid) with its per-scan change aggregate, for the
-- scan-detail API. The (tenant_id, uid) WHERE gate is the isolation boundary: a
-- cross-tenant or unknown uid returns no rows (pgx.ErrNoRows). Mirrors the
-- aggregate columns of ScansListByTenant and additionally returns the internal
-- scan id so the caller can fetch this scan's observations. Observation
-- aggregation is bounded to the single target scan and rides idx_obs_scan.
WITH target_scan AS (
    SELECT s.id, s.uid, s.domain_uid, s.domain_name, s.source,
           s.started_at, s.parent_scan_id
    FROM scans s
    WHERE s.tenant_id = @tenant_id
      AND s.uid = @uid
),
change_counts AS (
    SELECT o.scan_id, o.entity_type, o.change_type, count(*) AS n
    FROM domain_observations o
    WHERE o.scan_id IN (SELECT id FROM target_scan)
    GROUP BY o.scan_id, o.entity_type, o.change_type
),
per_scan AS (
    SELECT scan_id,
           COALESCE(sum(n) FILTER (WHERE change_type = 'created'), 0) AS created,
           COALESCE(sum(n) FILTER (WHERE change_type = 'updated'), 0) AS updated,
           COALESCE(sum(n) FILTER (WHERE change_type = 'deleted'), 0) AS deleted,
           jsonb_agg(jsonb_build_object(
               'entity_type', entity_type,
               'change_type', change_type,
               'count', n) ORDER BY entity_type, change_type) AS breakdown
    FROM change_counts
    GROUP BY scan_id
)
SELECT t.id                           AS scan_id,
       t.uid                          AS scan_uid,
       t.domain_uid,
       t.domain_name,
       t.source,
       t.started_at,
       p.uid                          AS parent_scan_uid,
       COALESCE(ps.created, 0)::int   AS created_count,
       COALESCE(ps.updated, 0)::int   AS updated_count,
       COALESCE(ps.deleted, 0)::int   AS deleted_count,
       COALESCE(ps.breakdown, '[]'::jsonb) AS breakdown
FROM target_scan t
         LEFT JOIN scans p ON p.id = t.parent_scan_id
         LEFT JOIN per_scan ps ON ps.scan_id = t.id;

-- name: ObservationsCreate :one
-- Append one change to the observation log.
INSERT INTO domain_observations (tenant_id, domain_id, domain_uid, domain_name, scan_id, entity_type, entity_key,
                                 change_type, payload)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, tenant_id, domain_id, domain_uid, domain_name, scan_id, entity_type, entity_key, change_type, payload, observed_at;

-- name: ObservationsCreateIfChanged :one
-- Append one change to the observation log, but only when the payload differs
-- from the most-recent prior observation for the same entity. Unchanged
-- re-observations insert nothing (the query returns no rows -> pgx.ErrNoRows,
-- which the caller treats as "suppressed"). change_type is 'created' on first
-- sighting, 'updated' otherwise. JSONB equality is value-level, so it is robust
-- to key ordering between the stored payload and the new one.
WITH latest AS (
    SELECT payload
    FROM domain_observations
    WHERE tenant_id = $1
      AND domain_name = $2
      AND entity_type = $3
      AND entity_key = $4
    ORDER BY observed_at DESC, id DESC
    LIMIT 1
)
INSERT INTO domain_observations (tenant_id, domain_id, domain_uid, domain_name, scan_id,
                                 entity_type, entity_key, change_type, payload)
SELECT $1, $5, $6, $2, $7, $3, $4,
       CASE WHEN NOT EXISTS (SELECT 1 FROM latest) THEN 'created' ELSE 'updated' END,
       sqlc.arg(payload)::jsonb
WHERE NOT EXISTS (SELECT 1 FROM latest WHERE latest.payload = sqlc.arg(payload)::jsonb)
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
-- All observations emitted during a single scan (scan-diff detail), tenant-scoped
-- for defense-in-depth even though callers verify scan ownership first.
SELECT id, tenant_id, domain_id, domain_uid, domain_name, scan_id, entity_type, entity_key, change_type, payload, observed_at
FROM domain_observations
WHERE scan_id = sqlc.arg(scan_id)
  AND tenant_id = sqlc.arg(tenant_id)
ORDER BY entity_type, entity_key;

-- name: ObservationsListTimelineByTenantDomainName :many
-- One-shot timeline: every observation for a (tenant, domain name) joined to its
-- scan (uid, source, started_at) and the scan's parent uid. The INNER JOIN to
-- scans means scans that recorded no changes never appear — the timeline is a
-- pure change history. Ordered newest-scan-first; callers group rows by scan uid.
SELECT o.id, o.tenant_id, o.domain_id, o.domain_uid, o.domain_name, o.scan_id,
       o.entity_type, o.entity_key, o.change_type, o.payload, o.observed_at,
       s.uid        AS scan_uid,
       s.source     AS scan_source,
       s.started_at AS scan_started_at,
       p.uid        AS parent_scan_uid
FROM domain_observations o
         JOIN scans s ON s.id = o.scan_id
         LEFT JOIN scans p ON p.id = s.parent_scan_id
WHERE o.tenant_id = $1
  AND o.domain_name = $2
ORDER BY s.started_at DESC, s.id DESC, o.id ASC;

-- name: ObservationsListWithScanUIDByTenantDomainName :many
-- Flat timeline for a (tenant, domain name) with each observation's scan uid
-- joined in, so the records-history API exposes scan_uid (never the numeric id)
-- without an N+1. LEFT JOIN keeps observations whose scan was detached (NULL).
SELECT o.id, o.tenant_id, o.domain_id, o.domain_uid, o.domain_name, o.scan_id,
       o.entity_type, o.entity_key, o.change_type, o.payload, o.observed_at,
       s.uid AS scan_uid
FROM domain_observations o
         LEFT JOIN scans s ON s.id = o.scan_id
WHERE o.tenant_id = $1
  AND o.domain_name = $2
ORDER BY o.observed_at DESC;
