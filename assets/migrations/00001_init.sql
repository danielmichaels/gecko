-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE
    OR REPLACE FUNCTION updated_at_trigger()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at
        = current_timestamp(0);
    RETURN NEW;
END;
$$
    LANGUAGE plpgsql;
-- Helper Function: generate_uid
CREATE OR REPLACE FUNCTION generate_uid(size INT) RETURNS TEXT AS
$$
DECLARE
    characters TEXT  := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    bytes      BYTEA := gen_random_bytes(size);
    l          INT   := length(characters);
    i          INT   := 0;
    output     TEXT  := '';
BEGIN
    WHILE i < size
        LOOP
            output := output || substr(characters, get_byte(bytes, i) % l + 1, 1);
            i := i + 1;
        END LOOP;
    RETURN output;
END;
$$ LANGUAGE plpgsql VOLATILE;
CREATE TYPE user_role AS ENUM (
    'owner', -- highest level of access in tenant
    'manager', -- manager level of access
    'viewer', -- lowest level of access
    'superadmin' -- doublestag super admin
    );
CREATE TABLE IF NOT EXISTS tenant
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('tenant_' || generate_uid(8)),
    name       VARCHAR(255)                NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0)
                   WITH TIME ZONE          NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS users
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('user_' || generate_uid(8)),
    tenant_id  INTEGER REFERENCES tenant (id) ON DELETE CASCADE,
    email      VARCHAR(255) UNIQUE         NOT NULL,
    name       VARCHAR(255),
    role       user_role                   NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_user_tenant_id ON users (tenant_id);
CREATE UNIQUE INDEX idx_user_email ON users (email);
CREATE TRIGGER trigger_updated_at_entity
    BEFORE UPDATE
    ON tenant
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_users
    BEFORE UPDATE
    ON users
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tenant CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TYPE IF EXISTS user_role;
DROP INDEX IF EXISTS idx_user_tenant_id;
DROP INDEX IF EXISTS idx_user_email;
DROP EXTENSION IF EXISTS "pgcrypto";
-- +goose StatementEnd
