-- +goose Up
-- +goose StatementBegin
-- finding_suppressions is the read-time side table that powers two user-facing
-- mechanisms without ever touching the 19 assessor finding tables (whose status
-- column is overwritten on every scan):
--
--   1. SILENCE RULE (forward-looking): mute a check by (kind, issue_type). A row
--      with domain_id NULL is tenant-global (all domains); a row with domain_id
--      set silences only that domain. finding_uid is NULL.
--   2. ACKNOWLEDGEMENT (per-instance): mark one specific finding handled/migrated.
--      Keyed by the finding's stable uid; kind/issue_type are NULL.
--
-- A finding is "suppressed" at read time iff a matching active row exists (see the
-- match predicate documented in internal/service/suppressions_match.go). Because
-- the table is keyed by stable identity (kind+issue_type) or the finding uid
-- (which survives ON CONFLICT upserts), suppression persists across re-scans.
CREATE TYPE suppression_state AS ENUM ('silenced', 'acknowledged', 'resolved');

CREATE TABLE finding_suppressions
(
    id          INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid         TEXT UNIQUE NOT NULL DEFAULT ('fsup_' || generate_uid(8)),
    tenant_id   INTEGER     NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- NULL = tenant-global rule; set = per-domain rule or the domain an ack belongs to.
    domain_id   INTEGER REFERENCES domains (id) ON DELETE CASCADE,
    kind        TEXT,        -- rule only (e.g. 'NS_CONFIG'); NULL for an ack
    issue_type  TEXT,        -- rule only (e.g. 'insufficient_nameservers'); NULL for an ack
    finding_uid TEXT,        -- ack only (stable finding uid); NULL for a rule
    state       suppression_state NOT NULL,
    reason      TEXT,
    created_by  INTEGER REFERENCES users (id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ, -- NULL = never expires (snooze support)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A row is exactly a rule or exactly an ack, never both, never neither.
    CONSTRAINT finding_suppressions_shape CHECK (
        (finding_uid IS NOT NULL AND kind IS NULL AND issue_type IS NULL)
            OR (finding_uid IS NULL AND kind IS NOT NULL AND issue_type IS NOT NULL)
        )
);

-- Uniqueness: partial because NULL domain_id/finding_uid distinguish the variants
-- and PostgreSQL treats NULLs as distinct in a plain unique index. These index
-- predicates are also the ON CONFLICT targets for the upsert queries.
CREATE UNIQUE INDEX finding_suppressions_global_rule_uq
    ON finding_suppressions (tenant_id, kind, issue_type)
    WHERE finding_uid IS NULL AND domain_id IS NULL;
CREATE UNIQUE INDEX finding_suppressions_domain_rule_uq
    ON finding_suppressions (domain_id, kind, issue_type)
    WHERE finding_uid IS NULL AND domain_id IS NOT NULL;
CREATE UNIQUE INDEX finding_suppressions_ack_uq
    ON finding_suppressions (finding_uid)
    WHERE finding_uid IS NOT NULL;

-- Read-path indexes for the suppression match join (rules by identity, acks by uid).
CREATE INDEX finding_suppressions_rule_lookup
    ON finding_suppressions (tenant_id, kind, issue_type)
    WHERE finding_uid IS NULL;
CREATE INDEX finding_suppressions_ack_lookup
    ON finding_suppressions (finding_uid)
    WHERE finding_uid IS NOT NULL;

CREATE TRIGGER trigger_updated_at_finding_suppressions
    BEFORE UPDATE
    ON finding_suppressions
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS finding_suppressions;
DROP TYPE IF EXISTS suppression_state;
-- +goose StatementEnd
