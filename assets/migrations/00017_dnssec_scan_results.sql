-- +goose Up
-- +goose StatementBegin
CREATE TABLE dnssec_scan_results
(
    id               SERIAL PRIMARY KEY,
    uid              TEXT UNIQUE                 NOT NULL DEFAULT ('dnssec_scan_' || generate_uid(8)),
    domain_id        INT REFERENCES domains (id) ON DELETE CASCADE,
    status           TEXT                        NOT NULL,
    validation_error TEXT,
    has_dnskey       BOOLEAN                     NOT NULL DEFAULT FALSE,
    has_ds           BOOLEAN                     NOT NULL DEFAULT FALSE,
    has_rrsig        BOOLEAN                     NOT NULL DEFAULT FALSE,
    algorithms       TEXT[]                      NOT NULL DEFAULT '{}',
    created_at       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id)
);

CREATE TRIGGER trigger_updated_at_dnssec_scan_results
    BEFORE UPDATE
    ON dnssec_scan_results
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE INDEX idx_dnssec_scan_results_domain_id ON dnssec_scan_results (domain_id);
CREATE INDEX idx_dnssec_scan_results_status ON dnssec_scan_results (status);

-- Enable upsert-dedup for the existing dnssec_findings table (was missing the
-- UNIQUE constraint every other findings table has).
ALTER TABLE dnssec_findings
    ADD CONSTRAINT dnssec_findings_domain_id_issue_type_key UNIQUE (domain_id, issue_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE dnssec_findings
    DROP CONSTRAINT IF EXISTS dnssec_findings_domain_id_issue_type_key;
DROP TRIGGER IF EXISTS trigger_updated_at_dnssec_scan_results ON dnssec_scan_results;
DROP TABLE IF EXISTS dnssec_scan_results;
-- +goose StatementEnd
