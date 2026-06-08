-- +goose Up
-- +goose StatementBegin
-- Drop the scs-shaped sessions table introduced in 00011 and replace it with the
-- hand-rolled session table used by the cookie-session system.
DROP TABLE IF EXISTS sessions CASCADE;

CREATE TABLE IF NOT EXISTS sessions
(
    id           SERIAL PRIMARY KEY,
    uid          TEXT UNIQUE                 NOT NULL DEFAULT ('session_' || generate_uid(8)),
    user_id      INTEGER                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id    INTEGER                     NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash   TEXT UNIQUE                 NOT NULL,
    expires_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    user_agent   TEXT,
    ip           TEXT,
    created_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX idx_sessions_user_id ON sessions (user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sessions CASCADE;

-- Restore the original scs-shaped sessions table.
CREATE TABLE IF NOT EXISTS sessions
(
    token  TEXT PRIMARY KEY,
    data   BYTEA       NOT NULL,
    expiry TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expiry_idx ON sessions (expiry);
-- +goose StatementEnd
