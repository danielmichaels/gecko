-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS password_reset_tokens
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('prt_' || generate_uid(8)),
    user_id    INTEGER                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE                 NOT NULL,
    expires_at TIMESTAMP(0) WITH TIME ZONE NOT NULL,
    used_at    TIMESTAMP(0) WITH TIME ZONE,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_prt_user_id ON password_reset_tokens (user_id);
CREATE INDEX idx_prt_expires_at ON password_reset_tokens (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
-- +goose StatementEnd
