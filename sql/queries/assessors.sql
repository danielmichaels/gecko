-- name: StoreZoneTransferFinding :one
INSERT INTO zone_transfer_findings (domain_id,
                                    ns_record_id,
                                    severity,
                                    status,
                                    nameserver,
                                    zone_transfer_possible,
                                    transfer_type,
                                    details,
                                    transfer_details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (domain_id, nameserver)
    DO UPDATE SET ns_record_id           = $2,
                  severity               = $3,
                  status                 = $4,
                  zone_transfer_possible = $6,
                  transfer_type          = $7,
                  details                = $8,
                  transfer_details       = $9
RETURNING (xmax = 0)::boolean AS inserted;

-- name: AssessCreateSPFFinding :one
INSERT INTO spf_findings (domain_id,
                          txt_record_id,
                          severity,
                          status,
                          issue_type,
                          spf_value,
                          details)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (domain_id, issue_type)
    DO UPDATE SET txt_record_id = $2,
                  severity      = $3,
                  status        = $4,
                  spf_value     = $6,
                  details       = $7
RETURNING (xmax = 0)::boolean AS inserted;

-- name: AssessGetSPFFindings :many
SELECT *
FROM spf_findings
WHERE domain_id = $1
ORDER BY severity ASC, created_at DESC;

-- name: AssessGetSPFFindingByDomainID :many
SELECT sf.*
FROM spf_findings sf
         JOIN domains d ON sf.domain_id = d.id
WHERE d.uid = $1
  AND d.tenant_id = $2
ORDER BY sf.severity ASC, sf.created_at DESC;

-- name: AssessCreateDKIMFinding :one
INSERT INTO dkim_findings (domain_id,
                           txt_record_id,
                           severity,
                           status,
                           selector,
                           issue_type,
                           dkim_value,
                           details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (domain_id, issue_type, selector)
WHERE selector IS NOT NULL
    DO UPDATE SET txt_record_id = $2,
                  severity      = $3,
                  status        = $4,
                  dkim_value    = $7,
                  details       = $8
RETURNING (xmax = 0)::boolean AS inserted;
-- name: AssessCreateDKIMFindingNoSelector :one
INSERT INTO dkim_findings (domain_id,
                           txt_record_id,
                           severity,
                           status,
                           selector,
                           issue_type,
                           dkim_value,
                           details)
VALUES ($1, $2, $3, $4, NULL, $5, $6, $7)
ON CONFLICT (domain_id, issue_type)
    WHERE (selector IS NULL)
    DO UPDATE SET txt_record_id = $2,
                  severity      = $3,
                  status        = $4,
                  dkim_value    = $6,
                  details       = $7
RETURNING (xmax = 0)::boolean AS inserted;

-- name: AssessGetDKIMFindings :many
SELECT *
FROM dkim_findings
WHERE domain_id = $1
ORDER BY severity ASC, created_at DESC;

-- name: AssessDKIMFindingsByDomainID :many
SELECT df.*
FROM dkim_findings df
         JOIN domains d ON df.domain_id = d.id
WHERE d.uid = $1
  AND d.tenant_id = $2
ORDER BY df.severity ASC, df.created_at DESC;

-- name: AssessCreateDMARCFinding :one
INSERT INTO dmarc_findings (domain_id,
                            txt_record_id,
                            severity,
                            status,
                            policy,
                            issue_type,
                            dmarc_value,
                            details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (domain_id, issue_type)
    DO UPDATE SET txt_record_id = $2,
                  severity      = $3,
                  status        = $4,
                  policy        = $5,
                  dmarc_value  = $7,
                  details       = $8
RETURNING (xmax = 0)::boolean AS inserted;

-- name: AssessGetDMARCFindings :many
SELECT *
FROM dmarc_findings
WHERE domain_id = $1
ORDER BY severity ASC, created_at DESC;

-- name: AssessGetDMARCFindingsByDomainID :many
SELECT df.*
FROM dmarc_findings df
         JOIN domains d ON df.domain_id = d.id
WHERE d.uid = $1
  AND d.tenant_id = $2
ORDER BY df.severity ASC, df.created_at DESC;

-- name: AssessGetZoneTransferFindings :many
SELECT id, uid, domain_id, ns_record_id, severity, status, nameserver, zone_transfer_possible,
       transfer_type, details, transfer_details, created_at, updated_at
FROM zone_transfer_findings
WHERE domain_id = $1
ORDER BY severity ASC, created_at DESC;

-- name: AssessGetZoneTransferFindingsByDomainUID :many
SELECT ztf.*
FROM zone_transfer_findings ztf
         JOIN domains d ON ztf.domain_id = d.id
WHERE d.uid = $1
  AND d.tenant_id = $2
ORDER BY ztf.severity ASC, ztf.created_at DESC;

-- name: DomainsListFindingsSummary :many
-- Worst open-finding severity + open-finding count per domain, for a page of
-- domain IDs. One round-trip for the whole page (no N+1). Only actionable
-- findings count: status='open' for email findings, zone_transfer_possible for
-- AXFR. severity_rank: critical=1 high=2 medium=3 low=4 info=5 none=6.
WITH ids AS (
    SELECT unnest(@domain_ids::int[]) AS domain_id
),
open_findings AS (
    SELECT domain_id, severity::text AS severity FROM spf_findings
        WHERE status = 'open' AND domain_id = ANY(@domain_ids::int[])
    UNION ALL
    SELECT domain_id, severity::text FROM dkim_findings
        WHERE status = 'open' AND domain_id = ANY(@domain_ids::int[])
    UNION ALL
    SELECT domain_id, severity::text FROM dmarc_findings
        WHERE status = 'open' AND domain_id = ANY(@domain_ids::int[])
    UNION ALL
    SELECT domain_id, severity::text FROM zone_transfer_findings
        WHERE zone_transfer_possible = true AND domain_id = ANY(@domain_ids::int[])
)
SELECT
    ids.domain_id::int AS domain_id,
    MIN(CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'low'      THEN 4
        WHEN 'info'     THEN 5
        ELSE 6
    END)::int AS severity_rank,
    COUNT(f.severity)::int AS finding_count
FROM ids
LEFT JOIN open_findings f ON f.domain_id = ids.domain_id
GROUP BY ids.domain_id;

-- name: FindingsListByTenant :many
-- Every finding across SPF/DKIM/DMARC/zone-transfer for one tenant, in a single
-- UNION ALL. Tenant scope is enforced transitively by the domains.tenant_id join
-- (the finding tables have no tenant_id) — this join IS the security boundary.
-- When @include_compliant is false, email findings are restricted to status='open'
-- and zone-transfer to actually-possible AXFRs. Ordered domain-then-severity so
-- the handler can group consecutively without a second sort.
SELECT f.finding_uid,
       f.domain_uid,
       f.domain_name,
       f.kind,
       f.severity,
       f.status,
       f.issue_type,
       f.value,
       f.details,
       f.selector,
       f.created_at
FROM (SELECT sf.uid                AS finding_uid,
             d.uid                 AS domain_uid,
             d.name                AS domain_name,
             'SPF'::text           AS kind,
             sf.severity           AS severity,
             sf.status             AS status,
             sf.issue_type         AS issue_type,
             sf.spf_value          AS value,
             sf.details            AS details,
             NULL::text            AS selector,
             sf.created_at         AS created_at
      FROM spf_findings sf
               JOIN domains d ON sf.domain_id = d.id
      WHERE d.tenant_id = @tenant_id
        AND (@include_compliant::bool OR sf.status = 'open')

      UNION ALL

      SELECT df.uid, d.uid, d.name, 'DKIM'::text, df.severity, df.status,
             df.issue_type, df.dkim_value, df.details, df.selector, df.created_at
      FROM dkim_findings df
               JOIN domains d ON df.domain_id = d.id
      WHERE d.tenant_id = @tenant_id
        AND (@include_compliant::bool OR df.status = 'open')

      UNION ALL

      SELECT mf.uid, d.uid, d.name, 'DMARC'::text, mf.severity, mf.status,
             mf.issue_type, mf.dmarc_value, mf.details, NULL::text, mf.created_at
      FROM dmarc_findings mf
               JOIN domains d ON mf.domain_id = d.id
      WHERE d.tenant_id = @tenant_id
        AND (@include_compliant::bool OR mf.status = 'open')

      UNION ALL

      SELECT zf.uid, d.uid, d.name, 'ZONE'::text, zf.severity, zf.status,
             CASE WHEN zf.zone_transfer_possible
                  THEN 'zone_transfer_exposed' ELSE 'zone_transfer_refused' END,
             zf.nameserver, zf.details, NULL::text, zf.created_at
      FROM zone_transfer_findings zf
               JOIN domains d ON zf.domain_id = d.id
      WHERE d.tenant_id = @tenant_id
        AND (@include_compliant::bool OR zf.zone_transfer_possible = true)) f
ORDER BY f.domain_name ASC,
         CASE f.severity
             WHEN 'critical' THEN 1
             WHEN 'high' THEN 2
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 4
             WHEN 'info' THEN 5
             ELSE 6
             END ASC,
         f.created_at ASC;

-- name: TenantFindingStatsAll :many
-- Per-tenant counts of domains whose worst open finding is critical/high
-- (critical_count) versus medium/low (warning_count), in a single grouped pass
-- over all tenants. Runs off the request path (periodic refresh job); the result
-- is cached into tenant_stats.
SELECT
    agg.tenant_id AS tenant_id,
    COUNT(*) FILTER (WHERE sev_rank <= 2)::int AS critical_count,
    COUNT(*) FILTER (WHERE sev_rank BETWEEN 3 AND 4)::int AS warning_count
FROM (
    SELECT d.tenant_id, d.id,
        MIN(CASE f.severity
            WHEN 'critical' THEN 1
            WHEN 'high'     THEN 2
            WHEN 'medium'   THEN 3
            WHEN 'low'      THEN 4
            WHEN 'info'     THEN 5
            ELSE 6
        END) AS sev_rank
    FROM domains d
    JOIN (
        SELECT domain_id, severity::text AS severity FROM spf_findings WHERE status = 'open'
        UNION ALL
        SELECT domain_id, severity::text FROM dkim_findings WHERE status = 'open'
        UNION ALL
        SELECT domain_id, severity::text FROM dmarc_findings WHERE status = 'open'
        UNION ALL
        SELECT domain_id, severity::text FROM zone_transfer_findings WHERE zone_transfer_possible = true
    ) f ON f.domain_id = d.id
    GROUP BY d.tenant_id, d.id
) agg
GROUP BY agg.tenant_id;
