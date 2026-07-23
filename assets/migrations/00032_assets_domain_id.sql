-- +goose Up
-- +goose StatementBegin
-- Give a domain-kind asset a real FK to its domain so an asset's lifecycle IS the
-- domain's. Without it, findings were reconnected to a domain by (tenant, name);
-- deleting then recreating a domain of the same name reused the orphaned asset row
-- and resurfaced the prior lifecycle's findings and history. ON DELETE CASCADE
-- propagates a domain delete through asset -> findings -> findings_events.
ALTER TABLE assets
    ADD COLUMN domain_id INTEGER REFERENCES domains (id) ON DELETE CASCADE;

UPDATE assets a
SET domain_id = d.id
FROM domains d
WHERE a.kind = 'domain'
  AND a.tenant_id = d.tenant_id
  AND a.value = d.name;

CREATE INDEX idx_assets_domain_id ON assets (domain_id) WHERE domain_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_assets_domain_id;
ALTER TABLE assets DROP COLUMN domain_id;
-- +goose StatementEnd
