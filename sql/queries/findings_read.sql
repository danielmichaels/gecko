-- Generic finding readers, sourced from the single `findings` table (replacing
-- the 19 typed per-check tables). A finding's domain is resolved via
-- findings.asset_id -> assets (kind='domain') -> domains (assets.domain_id = d.id):
-- a lifecycle FK, not the reusable name, so a deleted-then-recreated domain never
-- inherits the prior domain's findings. Tenant isolation is enforced directly on
-- findings.tenant_id, which is denormalized onto the row at write time.

-- name: FindingsListByDomainUID :many
-- Every open finding for one domain (identified by its uid, scoped to the
-- caller's tenant), worst-first.
SELECT f.*
FROM findings f
         JOIN assets a ON a.id = f.asset_id AND a.kind = 'domain'
         JOIN domains d ON d.id = a.domain_id
WHERE d.uid = @uid
  AND f.tenant_id = @tenant_id
  AND f.status = 'open'
ORDER BY CASE f.severity
             WHEN 'critical' THEN 1
             WHEN 'high' THEN 2
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 4
             WHEN 'info' THEN 5
             ELSE 6
             END ASC,
         f.first_seen ASC;

-- name: FindingsListTenantOpen :many
-- Every open finding across a tenant's domains, ordered domain-then-severity so
-- the caller can group consecutively without a second sort. Severity/kind/domain
-- filtering is applied in Go (buildTenantFindings) rather than here. Named
-- distinctly from assessors.sql's (soon-to-be-deleted) FindingsListByTenant.
SELECT f.uid        AS finding_uid,
       f.check_kind,
       f.issue_type,
       f.entity_key,
       f.severity,
       f.status,
       f.title,
       f.details,
       f.evidence,
       f.first_seen,
       d.uid         AS domain_uid,
       d.name        AS domain_name
FROM findings f
         JOIN assets a ON a.id = f.asset_id AND a.kind = 'domain'
         JOIN domains d ON d.id = a.domain_id
WHERE f.tenant_id = @tenant_id
  AND f.status = 'open'
ORDER BY d.name ASC,
         CASE f.severity
             WHEN 'critical' THEN 1
             WHEN 'high' THEN 2
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 4
             WHEN 'info' THEN 5
             ELSE 6
             END ASC,
         f.first_seen ASC;

-- name: FindingsSummaryByDomainIDs :many
-- Worst open-finding severity + count per domain, for a page of domain IDs (no
-- N+1). severity_rank: critical=1 high=2 medium=3 low=4 info=5 none=6. Feeds the
-- Domains list/detail row badges (DomainsService.FindingsSummaryForPage).
WITH ids AS (SELECT unnest(@domain_ids::int[]) AS domain_id),
     open_findings AS (SELECT d.id AS domain_id, f.severity
                        FROM findings f
                                 JOIN assets a ON a.id = f.asset_id AND a.kind = 'domain'
                                 JOIN domains d ON d.id = a.domain_id
                        WHERE f.status = 'open'
                          AND d.id = ANY (@domain_ids::int[]))
SELECT ids.domain_id::int                    AS domain_id,
       MIN(CASE ofd.severity
               WHEN 'critical' THEN 1
               WHEN 'high' THEN 2
               WHEN 'medium' THEN 3
               WHEN 'low' THEN 4
               WHEN 'info' THEN 5
               ELSE 6
           END)::int                         AS severity_rank,
       COUNT(ofd.severity)::int              AS finding_count
FROM ids
         LEFT JOIN open_findings ofd ON ofd.domain_id = ids.domain_id
GROUP BY ids.domain_id;

-- name: FindingsTenantStats :many
-- Per-tenant rollup of open findings: domains whose worst open finding is
-- critical/high (critical_count) vs medium/low (warning_count), the total open
-- finding count, and the distinct domain count with at least one open finding.
-- tenant_id narrows to a single tenant; NULL rolls up every tenant in one pass
-- (the periodic all-fleet refresh). Joined through assets/domains on the
-- assets.domain_id FK so a finding whose domain was deleted (the FK cascade removes
-- its asset + findings) never appears.
WITH per_domain AS (SELECT f.tenant_id,
                            f.asset_id,
                            MIN(CASE f.severity
                                    WHEN 'critical' THEN 1
                                    WHEN 'high' THEN 2
                                    WHEN 'medium' THEN 3
                                    WHEN 'low' THEN 4
                                    WHEN 'info' THEN 5
                                    ELSE 6
                                END) AS sev_rank,
                            COUNT(*) AS finding_count
                     FROM findings f
                              JOIN assets a ON a.id = f.asset_id AND a.kind = 'domain'
                              JOIN domains d ON d.id = a.domain_id
                     WHERE f.status = 'open'
                       AND (sqlc.narg('tenant_id')::int IS NULL OR f.tenant_id = sqlc.narg('tenant_id'))
                     GROUP BY f.tenant_id, f.asset_id)
SELECT tenant_id,
       COUNT(*) FILTER (WHERE sev_rank <= 2)::int            AS critical_count,
       COUNT(*) FILTER (WHERE sev_rank BETWEEN 3 AND 4)::int AS warning_count,
       SUM(finding_count)::int                               AS open_total,
       COUNT(*)::int                                         AS domain_count
FROM per_domain
GROUP BY tenant_id;
