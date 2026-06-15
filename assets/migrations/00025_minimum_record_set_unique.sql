-- +goose Up
-- +goose StatementBegin
ALTER TABLE minimum_record_set_findings
    ADD CONSTRAINT minimum_record_set_findings_domain_id_issue_type_key
        UNIQUE (domain_id, issue_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE minimum_record_set_findings
    DROP CONSTRAINT minimum_record_set_findings_domain_id_issue_type_key;
-- +goose StatementEnd
