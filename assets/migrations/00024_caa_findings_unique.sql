-- +goose Up
-- +goose StatementBegin
ALTER TABLE caa_configuration_findings
    ADD CONSTRAINT caa_configuration_findings_domain_id_issue_type_key
        UNIQUE (domain_id, issue_type);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE caa_compliance_findings
    ADD CONSTRAINT caa_compliance_findings_domain_id_issue_type_key
        UNIQUE (domain_id, issue_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE caa_configuration_findings
    DROP CONSTRAINT caa_configuration_findings_domain_id_issue_type_key;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE caa_compliance_findings
    DROP CONSTRAINT caa_compliance_findings_domain_id_issue_type_key;
-- +goose StatementEnd
