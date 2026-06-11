-- +goose Up
-- +goose StatementBegin
-- Enable upsert-dedup for the CNAME findings tables, which (like the old
-- dnssec_findings table) shipped without the UNIQUE constraint every other
-- findings table relies on for ON CONFLICT.
ALTER TABLE dangling_cname_findings
    ADD CONSTRAINT dangling_cname_findings_domain_id_target_domain_key UNIQUE (domain_id, target_domain);

ALTER TABLE cname_redirection_findings
    ADD CONSTRAINT cname_redirection_findings_domain_id_issue_type_key UNIQUE (domain_id, issue_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE cname_redirection_findings
    DROP CONSTRAINT IF EXISTS cname_redirection_findings_domain_id_issue_type_key;
ALTER TABLE dangling_cname_findings
    DROP CONSTRAINT IF EXISTS dangling_cname_findings_domain_id_target_domain_key;
-- +goose StatementEnd
