-- +goose Up
-- +goose StatementBegin
ALTER TABLE email_auth_compliance_findings
    ADD CONSTRAINT email_auth_compliance_findings_domain_auth_issue_key
        UNIQUE (domain_id, auth_type, issue_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE email_auth_compliance_findings
    DROP CONSTRAINT email_auth_compliance_findings_domain_auth_issue_key;
-- +goose StatementEnd
