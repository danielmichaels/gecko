-- +goose Up
-- +goose StatementBegin
-- assets is the thin, kind-agnostic spine that findings hang off. Phase 1 holds
-- one row per domain (kind='domain', 1:1); ip/host kinds drop in later as pure
-- data with zero schema change. parent_asset_id + is_cdn are the hooks the IP
-- wedge needs -- present now, unexercised until then. kind/value/source are TEXT
-- (not enums) so a new asset kind is zero-migration.
CREATE TABLE assets
(
    id              BIGSERIAL PRIMARY KEY,
    uid             TEXT UNIQUE                 NOT NULL DEFAULT ('asset_' || generate_uid(8)),
    tenant_id       INTEGER                     NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind            TEXT                        NOT NULL,
    value           TEXT                        NOT NULL,
    parent_asset_id BIGINT REFERENCES assets (id) ON DELETE CASCADE,
    is_cdn          BOOLEAN                     NOT NULL DEFAULT FALSE,
    source          TEXT                        NOT NULL DEFAULT 'discovered',
    first_seen      TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, kind, value)
);
CREATE INDEX idx_assets_tenant_kind ON assets (tenant_id, kind);
CREATE INDEX idx_assets_parent ON assets (parent_asset_id) WHERE parent_asset_id IS NOT NULL;

-- Backfill one asset per existing domain (1:1) so findings are born asset-keyed.
INSERT INTO assets (tenant_id, kind, value, source, first_seen, last_seen)
SELECT tenant_id, 'domain', name, source::text, created_at, updated_at
FROM domains
WHERE tenant_id IS NOT NULL
ON CONFLICT (tenant_id, kind, value) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE assets;
-- +goose StatementEnd
