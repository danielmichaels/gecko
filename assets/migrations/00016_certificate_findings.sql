-- +goose Up
-- +goose StatementBegin
CREATE TABLE certificate_findings
(
    id             SERIAL PRIMARY KEY,
    uid            TEXT UNIQUE                 NOT NULL DEFAULT ('cert_finding_' || generate_uid(8)),
    domain_id      INT REFERENCES domains (id) ON DELETE CASCADE,
    certificate_id INT REFERENCES certificates (id),
    severity       finding_severity            NOT NULL DEFAULT 'medium',
    status         finding_status              NOT NULL DEFAULT 'open',
    issue_type     TEXT                        NOT NULL,
    details        TEXT,
    created_at     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, issue_type)
);

CREATE TRIGGER trigger_updated_at_certificate_findings
    BEFORE UPDATE
    ON certificate_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE INDEX idx_certificate_findings_domain_id ON certificate_findings (domain_id);
CREATE INDEX idx_certificate_findings_severity ON certificate_findings (severity);
CREATE INDEX idx_certificate_findings_status ON certificate_findings (status);
CREATE INDEX idx_certificate_findings_issue_type ON certificate_findings (issue_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trigger_updated_at_certificate_findings ON certificate_findings;
DROP TABLE IF EXISTS certificate_findings;
-- +goose StatementEnd
