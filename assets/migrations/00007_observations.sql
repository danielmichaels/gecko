-- +goose Up
-- +goose StatementBegin
-- scans correlate every record/finding observed in a single domain scan so the
-- timeline can diff scan N vs N+1. Correlation IDs only: no status/finished_at,
-- because the callback fan-out model has no fan-in barrier to mark completion.
CREATE TABLE scans
(
    id             BIGSERIAL PRIMARY KEY,
    uid            TEXT UNIQUE                NOT NULL DEFAULT ('scan_' || generate_uid(8)),
    tenant_id      INT                        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    domain_id      INT REFERENCES domains (id) ON DELETE SET NULL,
    domain_uid     TEXT                       NOT NULL,
    domain_name    TEXT                       NOT NULL,
    parent_scan_id BIGINT REFERENCES scans (id) ON DELETE SET NULL,
    source         domain_source              NOT NULL DEFAULT 'user_supplied',
    started_at     TIMESTAMP(0) WITH TIME ZONE         DEFAULT NOW()
);

-- domain_observations is the single append-only change log that collapses the
-- per-table *_history shadow tables. Live tables stay as a current-state
-- projection; this log is the product-facing timeline.
CREATE TABLE domain_observations
(
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   INT                        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    domain_id   INT REFERENCES domains (id) ON DELETE SET NULL,
    domain_uid  TEXT                       NOT NULL,
    domain_name TEXT                       NOT NULL,
    scan_id     BIGINT REFERENCES scans (id) ON DELETE SET NULL,
    entity_type TEXT                       NOT NULL,
    entity_key  TEXT                       NOT NULL,
    change_type TEXT                       NOT NULL,
    payload     JSONB                      NOT NULL,
    observed_at TIMESTAMP(0) WITH TIME ZONE         DEFAULT NOW()
);

-- Deletion semantics are deliberately asymmetric:
--   DOMAIN deletion -> PRESERVE (domain_id SET NULL + denormalized identity), so
--     the timeline and its scan grouping survive a delete/re-add of the domain.
--   TENANT deletion -> PURGE (tenant_id CASCADE), full account erasure.
-- Reads MUST key on (tenant_id, domain_name) because domain_id goes NULL on delete.
CREATE INDEX idx_obs_tenant_name ON domain_observations (tenant_id, domain_name, observed_at DESC);
CREATE INDEX idx_obs_tenant_type ON domain_observations (tenant_id, domain_name, entity_type, observed_at DESC);
CREATE INDEX idx_obs_scan ON domain_observations (scan_id);
CREATE INDEX idx_scans_tenant_name ON scans (tenant_id, domain_name, started_at DESC);
CREATE INDEX idx_scans_parent ON scans (parent_scan_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scans_parent;
DROP INDEX IF EXISTS idx_scans_tenant_name;
DROP INDEX IF EXISTS idx_obs_scan;
DROP INDEX IF EXISTS idx_obs_tenant_type;
DROP INDEX IF EXISTS idx_obs_tenant_name;
DROP TABLE IF EXISTS domain_observations;
DROP TABLE IF EXISTS scans;
-- +goose StatementEnd
