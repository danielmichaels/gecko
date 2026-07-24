-- +goose Up
-- +goose StatementBegin

-- Collect/detect flip: the 19 typed per-check finding tables (and their history
-- tables + triggers) are replaced by the single generic `findings` table
-- (00030). CASCADE removes each table's triggers, indexes, and the
-- history-table FKs that point back at their parents. Evidence tables
-- (zone_transfer_attempts, dnssec_scan_results) and the transfer_type enum are
-- deliberately kept.
DROP TABLE IF EXISTS
    spf_findings, spf_findings_history,
    dkim_findings, dkim_findings_history,
    dmarc_findings, dmarc_findings_history,
    email_auth_compliance_findings, email_auth_compliance_findings_history,
    dnssec_findings, dnssec_findings_history,
    dnssec_compliance_findings, dnssec_compliance_findings_history,
    certificate_findings,
    cname_redirection_findings, cname_redirection_findings_history,
    dangling_cname_findings, dangling_cname_findings_history,
    zone_transfer_findings, zone_transfer_findings_history,
    ns_configuration_findings, ns_configuration_findings_history,
    nameserver_reachability_findings, nameserver_reachability_findings_history,
    nameserver_redundancy_findings, nameserver_redundancy_findings_history,
    caa_configuration_findings, caa_configuration_findings_history,
    caa_compliance_findings, caa_compliance_findings_history,
    dns_resolution_consistency_findings, dns_resolution_consistency_findings_history,
    dns_resolution_latency_findings, dns_resolution_latency_findings_history,
    minimum_record_set_findings, minimum_record_set_findings_history,
    open_port_findings, open_port_findings_history
    CASCADE;

-- Orphaned finding-history trigger functions (their triggers went with the
-- tables above). record_zone_transfer_attempts_history and the DNS-record
-- history functions are untouched — different subsystems.
DROP FUNCTION IF EXISTS record_spf_history();
DROP FUNCTION IF EXISTS record_dkim_history();
DROP FUNCTION IF EXISTS record_dmarc_history();
DROP FUNCTION IF EXISTS record_email_auth_compliance_history();
DROP FUNCTION IF EXISTS record_dnssec_history();
DROP FUNCTION IF EXISTS record_dnssec_compliance_history();
DROP FUNCTION IF EXISTS record_cname_redirection_history();
DROP FUNCTION IF EXISTS record_dangling_cname_history();
DROP FUNCTION IF EXISTS record_zone_transfer_history();
DROP FUNCTION IF EXISTS record_ns_configuration_history();
DROP FUNCTION IF EXISTS record_nameserver_reachability_history();
DROP FUNCTION IF EXISTS record_nameserver_redundancy_history();
DROP FUNCTION IF EXISTS record_caa_configuration_history();
DROP FUNCTION IF EXISTS record_caa_compliance_history();
DROP FUNCTION IF EXISTS record_dns_resolution_consistency_history();
DROP FUNCTION IF EXISTS record_dns_resolution_latency_history();
DROP FUNCTION IF EXISTS record_minimum_record_set_history();
DROP FUNCTION IF EXISTS record_open_port_history();

-- No table references these enums once the finding tables are gone. transfer_type
-- stays (shared with the kept zone_transfer_attempts evidence table).
DROP TYPE IF EXISTS finding_severity;
DROP TYPE IF EXISTS finding_status;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Scorched-earth flip: the typed finding subsystem is not restored. Rolling this
-- migration back leaves the generic findings table (00030) as the sole store.
SELECT 1;
-- +goose StatementEnd
