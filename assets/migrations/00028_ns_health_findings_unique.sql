-- +goose Up
-- +goose StatementBegin
ALTER TABLE nameserver_reachability_findings
    ADD CONSTRAINT nameserver_reachability_findings_domain_ns_issue_key
        UNIQUE (domain_id, nameserver, issue_type);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE dns_resolution_latency_findings
    ADD CONSTRAINT dns_resolution_latency_findings_domain_resolver_type_key
        UNIQUE (domain_id, resolver, record_type);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE dns_resolution_consistency_findings
    ADD CONSTRAINT dns_resolution_consistency_findings_domain_type_key
        UNIQUE (domain_id, record_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE nameserver_reachability_findings
    DROP CONSTRAINT nameserver_reachability_findings_domain_ns_issue_key;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE dns_resolution_latency_findings
    DROP CONSTRAINT dns_resolution_latency_findings_domain_resolver_type_key;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE dns_resolution_consistency_findings
    DROP CONSTRAINT dns_resolution_consistency_findings_domain_type_key;
-- +goose StatementEnd
