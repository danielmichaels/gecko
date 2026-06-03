-- +goose Up
-- +goose StatementBegin
-- Decommission the remaining trigger-driven *_history shadow tables now that the
-- observation log covers the written types (zone_transfer_attempts via the
-- scanner; SPF/DKIM/DMARC/zone-transfer findings via the assessor) and the
-- never-written types (certificates + the unwritten finding tables) have empty,
-- dead history. This removes the last of the shadow-table audit pattern.
--
-- DROP FUNCTION ... CASCADE also drops the triggers on the live tables that call
-- each function, so they don't need to be enumerated. updated_at_trigger() is
-- unrelated to history and is kept.

-- Certificates (00003)
DROP FUNCTION IF EXISTS record_certificate_history() CASCADE;
DROP TABLE IF EXISTS certificates_history CASCADE;

-- Assessor findings (00005)
DROP FUNCTION IF EXISTS record_dangling_cname_history() CASCADE;
DROP FUNCTION IF EXISTS record_zone_transfer_history() CASCADE;
DROP FUNCTION IF EXISTS record_dnssec_history() CASCADE;
DROP FUNCTION IF EXISTS record_spf_history() CASCADE;
DROP FUNCTION IF EXISTS record_dkim_history() CASCADE;
DROP FUNCTION IF EXISTS record_dmarc_history() CASCADE;
DROP FUNCTION IF EXISTS record_open_port_history() CASCADE;
DROP FUNCTION IF EXISTS record_cname_redirection_history() CASCADE;
DROP FUNCTION IF EXISTS record_ns_configuration_history() CASCADE;
DROP FUNCTION IF EXISTS record_caa_configuration_history() CASCADE;
DROP FUNCTION IF EXISTS record_dns_resolution_consistency_history() CASCADE;
DROP FUNCTION IF EXISTS record_dns_resolution_latency_history() CASCADE;
DROP FUNCTION IF EXISTS record_nameserver_reachability_history() CASCADE;
DROP FUNCTION IF EXISTS record_dnssec_compliance_history() CASCADE;
DROP FUNCTION IF EXISTS record_email_auth_compliance_history() CASCADE;
DROP FUNCTION IF EXISTS record_caa_compliance_history() CASCADE;
DROP FUNCTION IF EXISTS record_nameserver_redundancy_history() CASCADE;
DROP FUNCTION IF EXISTS record_minimum_record_set_history() CASCADE;

DROP TABLE IF EXISTS dangling_cname_findings_history CASCADE;
DROP TABLE IF EXISTS zone_transfer_findings_history CASCADE;
DROP TABLE IF EXISTS dnssec_findings_history CASCADE;
DROP TABLE IF EXISTS spf_findings_history CASCADE;
DROP TABLE IF EXISTS dkim_findings_history CASCADE;
DROP TABLE IF EXISTS dmarc_findings_history CASCADE;
DROP TABLE IF EXISTS open_port_findings_history CASCADE;
DROP TABLE IF EXISTS cname_redirection_findings_history CASCADE;
DROP TABLE IF EXISTS ns_configuration_findings_history CASCADE;
DROP TABLE IF EXISTS caa_configuration_findings_history CASCADE;
DROP TABLE IF EXISTS dns_resolution_consistency_findings_history CASCADE;
DROP TABLE IF EXISTS dns_resolution_latency_findings_history CASCADE;
DROP TABLE IF EXISTS nameserver_reachability_findings_history CASCADE;
DROP TABLE IF EXISTS dnssec_compliance_findings_history CASCADE;
DROP TABLE IF EXISTS email_auth_compliance_findings_history CASCADE;
DROP TABLE IF EXISTS caa_compliance_findings_history CASCADE;
DROP TABLE IF EXISTS nameserver_redundancy_findings_history CASCADE;
DROP TABLE IF EXISTS minimum_record_set_findings_history CASCADE;

-- Zone transfer attempts (00006), incl. the delete_zone_transfer_history
-- workaround trigger on the domains table (CASCADE drops domains_delete_trigger).
DROP FUNCTION IF EXISTS record_zone_transfer_attempts_history() CASCADE;
DROP FUNCTION IF EXISTS delete_zone_transfer_history() CASCADE;
DROP TABLE IF EXISTS zone_transfer_attempts_history CASCADE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Intentionally not reversed. This migration retires the last of the legacy
-- shadow-table audit pattern; the observation log (00007) is the replacement.
-- Recreating ~20 history tables + functions + triggers would be dead code, and
-- the project is pre-alpha with a clean slate, so down is a deliberate no-op.
SELECT 1;
-- +goose StatementEnd
