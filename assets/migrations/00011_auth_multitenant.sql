-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
    ALTER COLUMN status DROP DEFAULT;
ALTER TABLE users
    ALTER COLUMN status TYPE user_status USING status::user_status;
ALTER TABLE users
    ALTER COLUMN status SET DEFAULT 'active'::user_status;

CREATE TABLE IF NOT EXISTS user_credentials
(
    id            SERIAL PRIMARY KEY,
    user_id       INTEGER UNIQUE              NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    password_hash TEXT                        NOT NULL,
    created_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE TRIGGER trigger_updated_at_user_credentials
    BEFORE UPDATE
    ON user_credentials
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TABLE IF NOT EXISTS api_keys
(
    id           SERIAL PRIMARY KEY,
    uid          TEXT UNIQUE                 NOT NULL DEFAULT ('apikey_' || generate_uid(8)),
    tenant_id    INTEGER                     NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id      INTEGER                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         VARCHAR(255)                NOT NULL,
    prefix       TEXT UNIQUE                 NOT NULL,
    key_hash     TEXT                        NOT NULL,
    last_used_at TIMESTAMP(0) WITH TIME ZONE,
    expires_at   TIMESTAMP(0) WITH TIME ZONE,
    revoked_at   TIMESTAMP(0) WITH TIME ZONE,
    created_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_api_keys_prefix ON api_keys (prefix);
CREATE INDEX idx_api_keys_tenant_id ON api_keys (tenant_id);

CREATE TABLE IF NOT EXISTS invitations
(
    id          SERIAL PRIMARY KEY,
    uid         TEXT UNIQUE                 NOT NULL DEFAULT ('invite_' || generate_uid(8)),
    tenant_id   INTEGER                     NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email       VARCHAR(255)                NOT NULL,
    role        user_role                   NOT NULL,
    token_hash  TEXT UNIQUE                 NOT NULL,
    invited_by  INTEGER REFERENCES users (id) ON DELETE SET NULL,
    expires_at  TIMESTAMP(0) WITH TIME ZONE NOT NULL,
    accepted_at TIMESTAMP(0) WITH TIME ZONE,
    created_at  TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_invitations_open_email ON invitations (tenant_id, email) WHERE accepted_at IS NULL;
CREATE INDEX idx_invitations_tenant_id ON invitations (tenant_id);

CREATE TABLE IF NOT EXISTS sessions
(
    token  TEXT PRIMARY KEY,
    data   BYTEA       NOT NULL,
    expiry TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expiry_idx ON sessions (expiry);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS invitations CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;
DROP TABLE IF EXISTS user_credentials CASCADE;
ALTER TABLE users
    ALTER COLUMN status DROP DEFAULT;
ALTER TABLE users
    ALTER COLUMN status TYPE VARCHAR(20) USING status::text;
ALTER TABLE users
    ALTER COLUMN status SET DEFAULT 'active';
-- +goose StatementEnd
