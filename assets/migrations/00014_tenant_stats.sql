-- +goose Up
-- +goose StatementBegin
CREATE TABLE tenant_stats (
    tenant_id      INTEGER     NOT NULL UNIQUE REFERENCES tenants (id) ON DELETE CASCADE,
    record_total   BIGINT      NOT NULL DEFAULT 0,
    critical_count INTEGER     NOT NULL DEFAULT 0,
    warning_count  INTEGER     NOT NULL DEFAULT 0,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tenant_stats;
-- +goose StatementEnd
