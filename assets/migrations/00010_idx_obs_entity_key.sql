-- +goose Up
-- +goose StatementBegin
-- Supports ObservationsCreateIfChanged: the no-op-suppression path looks up the
-- most-recent prior observation for an entity, filtering on
-- (tenant_id, domain_name, entity_type, entity_key) ordered by (observed_at, id)
-- DESC. The existing idx_obs_tenant_type stops at entity_type; adding entity_key
-- (and the order columns) lets that LIMIT 1 lookup be served from the index.
CREATE INDEX idx_obs_entity_key ON domain_observations
    (tenant_id, domain_name, entity_type, entity_key, observed_at DESC, id DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_obs_entity_key;
-- +goose StatementEnd
