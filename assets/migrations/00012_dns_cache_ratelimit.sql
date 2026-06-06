-- +goose Up
-- +goose StatementBegin
CREATE TABLE dns_cache (
    qtype      INTEGER     NOT NULL,
    fqdn       TEXT        NOT NULL,
    answers    TEXT[]      NOT NULL DEFAULT '{}',
    status     SMALLINT    NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (qtype, fqdn)
);
CREATE INDEX idx_dns_cache_expires ON dns_cache (expires_at);

CREATE TABLE dns_rate_limit_bucket (
    key         TEXT PRIMARY KEY,
    tokens      DOUBLE PRECISION NOT NULL,
    last_refill TIMESTAMPTZ      NOT NULL DEFAULT now(),
    rate_qps    DOUBLE PRECISION NOT NULL,
    burst       DOUBLE PRECISION NOT NULL,
    updated_at  TIMESTAMPTZ      NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dns_rate_limit_bucket;
DROP TABLE IF EXISTS dns_cache;
-- +goose StatementEnd
