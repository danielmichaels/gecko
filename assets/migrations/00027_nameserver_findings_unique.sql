-- +goose Up
-- +goose StatementBegin
ALTER TABLE ns_configuration_findings
    ADD CONSTRAINT ns_configuration_findings_domain_ns_issue_key
        UNIQUE (domain_id, nameserver, issue_type);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE nameserver_redundancy_findings
    ADD CONSTRAINT nameserver_redundancy_findings_domain_issue_key
        UNIQUE (domain_id, issue_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ns_configuration_findings
    DROP CONSTRAINT ns_configuration_findings_domain_ns_issue_key;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE nameserver_redundancy_findings
    DROP CONSTRAINT nameserver_redundancy_findings_domain_issue_key;
-- +goose StatementEnd
