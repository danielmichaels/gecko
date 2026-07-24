-- +goose Up
-- +goose StatementBegin
-- findings is the single generic findings table replacing the 19 typed tables.
-- A finding is a problem TRUE NOW for (asset, check, issue_type, entity_key);
-- compliant/NA is modelled as the row's absence. status is binary open|resolved.
-- The identity key is the reconciler's linchpin: a stable key keeps a recurring
-- problem the same row across scans (no close+reopen churn).
CREATE TABLE findings
(
    id          BIGSERIAL PRIMARY KEY,
    uid         TEXT UNIQUE                 NOT NULL DEFAULT ('finding_' || generate_uid(8)),
    tenant_id   INTEGER                     NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    asset_id    BIGINT                      NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    check_kind  TEXT                        NOT NULL,
    issue_type  TEXT                        NOT NULL,
    entity_key  TEXT                        NOT NULL DEFAULT '',
    severity    TEXT                        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status      TEXT                        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    title       TEXT                        NOT NULL DEFAULT '',
    details     TEXT                        NOT NULL DEFAULT '',
    evidence    JSONB,
    first_seen  TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMP(0) WITH TIME ZONE,
    UNIQUE (tenant_id, asset_id, check_kind, issue_type, entity_key)
);
CREATE INDEX idx_findings_asset_check ON findings (asset_id, check_kind);
CREATE INDEX idx_findings_tenant_status ON findings (tenant_id, status);

-- findings_events is the append-only flip history: one row per open/resolved/
-- reopened transition. findings.resolved_at stays as a denormalized current-state
-- column for the cheap "open + recently-resolved" query; this table holds the
-- full lifecycle for the product timeline.
CREATE TABLE findings_events
(
    id         BIGSERIAL PRIMARY KEY,
    finding_id BIGINT                      NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    event      TEXT                        NOT NULL CHECK (event IN ('opened', 'resolved', 'reopened')),
    at         TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_findings_events_finding ON findings_events (finding_id, at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE findings_events;
DROP TABLE findings;
-- +goose StatementEnd
