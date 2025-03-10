-- +goose Up
-- +goose StatementBegin
CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE finding_status AS ENUM ('open', 'resolved', 'false_positive', 'accepted_risk');
CREATE TYPE transfer_type AS ENUM ('AXFR', 'IXFR', 'AXFR+IXFR' );

-- I. Security Assessors Tables
-- 1. Dangling CNAME Assessor
CREATE TABLE dangling_cname_findings
(
    id                SERIAL PRIMARY KEY,
    uid               TEXT UNIQUE                 NOT NULL DEFAULT ('dangling_cname_' || generate_uid(8)),
    domain_id         INT REFERENCES domains (id) ON DELETE CASCADE,
    severity          finding_severity            NOT NULL DEFAULT 'high',
    status            finding_status              NOT NULL DEFAULT 'open',
    target_domain     TEXT                        NOT NULL,
    service_provider  TEXT,
    takeover_possible BOOLEAN                     NOT NULL DEFAULT FALSE,
    details           TEXT,
    created_at        TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 2. Zone Transfer Assessor
CREATE TABLE zone_transfer_findings
(
    id                     SERIAL PRIMARY KEY,
    uid                    TEXT UNIQUE                 NOT NULL DEFAULT ('zone_transfer_' || generate_uid(8)),
    domain_id              INT REFERENCES domains (id) ON DELETE CASCADE,
    ns_record_id           INT REFERENCES ns_records (id),
    severity               finding_severity            NOT NULL DEFAULT 'high',
    status                 finding_status              NOT NULL DEFAULT 'open',
    nameserver             TEXT                        NOT NULL,
    zone_transfer_possible BOOLEAN                     NOT NULL DEFAULT FALSE,
    transfer_type          transfer_type               NOT NULL,
    details                TEXT,
    created_at             TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, nameserver)
);
-- 3. DNSSEC Assessor
CREATE TABLE dnssec_findings
(
    id               SERIAL PRIMARY KEY,
    uid              TEXT UNIQUE                 NOT NULL DEFAULT ('dnssec_' || generate_uid(8)),
    domain_id        INT REFERENCES domains (id) ON DELETE CASCADE,
    dnskey_record_id INT REFERENCES dnskey_records (id),
    ds_record_id     INT REFERENCES ds_records (id),
    severity         finding_severity            NOT NULL DEFAULT 'medium',
    status           finding_status              NOT NULL DEFAULT 'open',
    issue_type       TEXT                        NOT NULL, -- e.g., "missing_ds", "algorithm_mismatch", "key_rollover_needed"
    details          TEXT,
    created_at       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 4. SPF Record Assessor
CREATE TABLE spf_findings
(
    id            SERIAL PRIMARY KEY,
    uid           TEXT UNIQUE                 NOT NULL DEFAULT ('spf_' || generate_uid(8)),
    domain_id     INT REFERENCES domains (id) ON DELETE CASCADE,
    txt_record_id INT REFERENCES txt_records (id),
    severity      finding_severity            NOT NULL DEFAULT 'medium',
    status        finding_status              NOT NULL DEFAULT 'open',
    issue_type    TEXT                        NOT NULL, -- e.g., "missing_spf", "too_many_lookups", "invalid_syntax"
    spf_value     TEXT,
    details       TEXT,
    created_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 5. DKIM Record Assessor
CREATE TABLE dkim_findings
(
    id            SERIAL PRIMARY KEY,
    uid           TEXT UNIQUE                 NOT NULL DEFAULT ('dkim_' || generate_uid(8)),
    domain_id     INT REFERENCES domains (id) ON DELETE CASCADE,
    txt_record_id INT REFERENCES txt_records (id),
    severity      finding_severity            NOT NULL DEFAULT 'medium',
    status        finding_status              NOT NULL DEFAULT 'open',
    selector      TEXT,
    issue_type    TEXT                        NOT NULL, -- e.g., "missing_dkim", "weak_key", "expired_key"
    details       TEXT,
    created_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 6. DMARC Record Assessor
CREATE TABLE dmarc_findings
(
    id            SERIAL PRIMARY KEY,
    uid           TEXT UNIQUE                 NOT NULL DEFAULT ('dmarc_' || generate_uid(8)),
    domain_id     INT REFERENCES domains (id) ON DELETE CASCADE,
    txt_record_id INT REFERENCES txt_records (id),
    severity      finding_severity            NOT NULL DEFAULT 'medium',
    status        finding_status              NOT NULL DEFAULT 'open',
    policy        TEXT,                                 -- p=none, p=quarantine, p=reject
    issue_type    TEXT                        NOT NULL, -- e.g., "missing_dmarc", "weak_policy", "missing_reporting"
    details       TEXT,
    created_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 7. Open Port Assessor
CREATE TABLE open_port_findings
(
    id             SERIAL PRIMARY KEY,
    uid            TEXT UNIQUE                 NOT NULL DEFAULT ('open_port_' || generate_uid(8)),
    domain_id      INT REFERENCES domains (id) ON DELETE CASCADE,
    a_record_id    INT REFERENCES a_records (id),
    aaaa_record_id INT REFERENCES aaaa_records (id),
    severity       finding_severity            NOT NULL DEFAULT 'medium',
    status         finding_status              NOT NULL DEFAULT 'open',
    ip_address     TEXT                        NOT NULL,
    port           INT                         NOT NULL,
    service        TEXT,
    issue_type     TEXT                        NOT NULL, -- e.g., "unexpected_open_port", "vulnerable_service"
    details        TEXT,
    created_at     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 8. CNAME Redirection Assessor
CREATE TABLE cname_redirection_findings
(
    id              SERIAL PRIMARY KEY,
    uid             TEXT UNIQUE                 NOT NULL DEFAULT ('cname_redirection_' || generate_uid(8)),
    domain_id       INT REFERENCES domains (id) ON DELETE CASCADE,
    cname_record_id INT REFERENCES cname_records (id),
    severity        finding_severity            NOT NULL DEFAULT 'medium',
    status          finding_status              NOT NULL DEFAULT 'open',
    issue_type      TEXT                        NOT NULL, -- e.g., "cname_loop", "long_chain", "points_to_ip"
    chain_length    INT,
    details         TEXT,
    created_at      TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 9. NS Configuration Assessor
CREATE TABLE ns_configuration_findings
(
    id           SERIAL PRIMARY KEY,
    uid          TEXT UNIQUE                 NOT NULL DEFAULT ('ns_config_' || generate_uid(8)),
    domain_id    INT REFERENCES domains (id) ON DELETE CASCADE,
    ns_record_id INT REFERENCES ns_records (id),
    severity     finding_severity            NOT NULL DEFAULT 'medium',
    status       finding_status              NOT NULL DEFAULT 'open',
    issue_type   TEXT                        NOT NULL, -- e.g., "ns_change_detected", "unknown_nameserver", "single_ns"
    nameserver   TEXT                        NOT NULL,
    details      TEXT,
    created_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 10. CAA Configuration Assessor
CREATE TABLE caa_configuration_findings
(
    id            SERIAL PRIMARY KEY,
    uid           TEXT UNIQUE                 NOT NULL DEFAULT ('caa_config_' || generate_uid(8)),
    domain_id     INT REFERENCES domains (id) ON DELETE CASCADE,
    caa_record_id INT REFERENCES caa_records (id),
    severity      finding_severity            NOT NULL DEFAULT 'medium',
    status        finding_status              NOT NULL DEFAULT 'open',
    issue_type    TEXT                        NOT NULL, -- e.g., "missing_caa", "misconfigured_caa", "insufficient_policy"
    details       TEXT,
    created_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- II. Operational Assessors Tables
-- 11. DNS Resolution Consistency Assessor
CREATE TABLE dns_resolution_consistency_findings
(
    id               SERIAL PRIMARY KEY,
    uid              TEXT UNIQUE                 NOT NULL DEFAULT ('dns_consistency_' || generate_uid(8)),
    domain_id        INT REFERENCES domains (id) ON DELETE CASCADE,
    severity         finding_severity            NOT NULL DEFAULT 'medium',
    status           finding_status              NOT NULL DEFAULT 'open',
    record_type      TEXT                        NOT NULL, -- A, AAAA, MX, etc.
    resolver1        TEXT                        NOT NULL,
    resolver1_result TEXT,
    resolver2        TEXT                        NOT NULL,
    resolver2_result TEXT,
    details          TEXT,
    created_at       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 12. DNS Resolution Latency Assessor
CREATE TABLE dns_resolution_latency_findings
(
    id           SERIAL PRIMARY KEY,
    uid          TEXT UNIQUE                 NOT NULL DEFAULT ('dns_latency_' || generate_uid(8)),
    domain_id    INT REFERENCES domains (id) ON DELETE CASCADE,
    severity     finding_severity            NOT NULL DEFAULT 'low',
    status       finding_status              NOT NULL DEFAULT 'open',
    record_type  TEXT                        NOT NULL, -- A, AAAA, MX, etc.
    resolver     TEXT                        NOT NULL,
    latency_ms   INT                         NOT NULL,
    threshold_ms INT                         NOT NULL, -- The threshold that was exceeded
    details      TEXT,
    created_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 13. Nameserver Reachability Assessor
CREATE TABLE nameserver_reachability_findings
(
    id               SERIAL PRIMARY KEY,
    uid              TEXT UNIQUE                 NOT NULL DEFAULT ('ns_reachability_' || generate_uid(8)),
    domain_id        INT REFERENCES domains (id) ON DELETE CASCADE,
    ns_record_id     INT REFERENCES ns_records (id),
    severity         finding_severity            NOT NULL DEFAULT 'high',
    status           finding_status              NOT NULL DEFAULT 'open',
    nameserver       TEXT                        NOT NULL,
    issue_type       TEXT                        NOT NULL, -- e.g., "unreachable", "slow_response", "timeout"
    response_time_ms INT,
    details          TEXT,
    created_at       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- III. Compliance & Best Practices Assessors Tables
-- 14. DNSSEC Compliance Assessor
CREATE TABLE dnssec_compliance_findings
(
    id            SERIAL PRIMARY KEY,
    uid           TEXT UNIQUE                 NOT NULL DEFAULT ('dnssec_compliance_' || generate_uid(8)),
    domain_id     INT REFERENCES domains (id) ON DELETE CASCADE,
    severity      finding_severity            NOT NULL DEFAULT 'medium',
    status        finding_status              NOT NULL DEFAULT 'open',
    issue_type    TEXT                        NOT NULL, -- e.g., "non_compliant_algorithm", "key_size_too_small", "missing_records"
    standard_name TEXT,                                 -- e.g., "NIST SP 800-57", "RFC 8624"
    details       TEXT,
    created_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 15. Email Auth Compliance Assessor
CREATE TABLE email_auth_compliance_findings
(
    id            SERIAL PRIMARY KEY,
    uid           TEXT UNIQUE                 NOT NULL DEFAULT ('email_auth_compliance_' || generate_uid(8)),
    domain_id     INT REFERENCES domains (id) ON DELETE CASCADE,
    txt_record_id INT REFERENCES txt_records (id),
    severity      finding_severity            NOT NULL DEFAULT 'medium',
    status        finding_status              NOT NULL DEFAULT 'open',
    auth_type     TEXT                        NOT NULL, -- SPF, DKIM, DMARC
    issue_type    TEXT                        NOT NULL, -- e.g., "non_compliant_syntax", "policy_too_weak", "missing_recommended_tags"
    standard_name TEXT,                                 -- e.g., "M3AAWG", "NIST SP 800-177"
    details       TEXT,
    created_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 16. CAA Compliance Assessor
CREATE TABLE caa_compliance_findings
(
    id            SERIAL PRIMARY KEY,
    uid           TEXT UNIQUE                 NOT NULL DEFAULT ('caa_compliance_' || generate_uid(8)),
    domain_id     INT REFERENCES domains (id) ON DELETE CASCADE,
    caa_record_id INT REFERENCES caa_records (id),
    severity      finding_severity            NOT NULL DEFAULT 'medium',
    status        finding_status              NOT NULL DEFAULT 'open',
    issue_type    TEXT                        NOT NULL, -- e.g., "missing_wildcard_policy", "missing_iodef"
    standard_name TEXT,                                 -- e.g., "CAA RFC 8659"
    details       TEXT,
    created_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
-- 18. Nameserver Redundancy Assessor
CREATE TABLE nameserver_redundancy_findings
(
    id                SERIAL PRIMARY KEY,
    uid               TEXT UNIQUE                 NOT NULL DEFAULT ('ns_redundancy_' || generate_uid(8)),
    domain_id         INT REFERENCES domains (id) ON DELETE CASCADE,
    severity          finding_severity            NOT NULL DEFAULT 'medium',
    status            finding_status              NOT NULL DEFAULT 'open',
    issue_type        TEXT                        NOT NULL, -- e.g., "insufficient_nameservers", "same_network", "same_provider"
    nameserver_count  INT                         NOT NULL,
    recommended_count INT                         NOT NULL,
    details           TEXT,
    created_at        TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 19. Minimum Record Set Assessor
CREATE TABLE minimum_record_set_findings
(
    id                  SERIAL PRIMARY KEY,
    uid                 TEXT UNIQUE                 NOT NULL DEFAULT ('min_record_set_' || generate_uid(8)),
    domain_id           INT REFERENCES domains (id) ON DELETE CASCADE,
    severity            finding_severity            NOT NULL DEFAULT 'low',
    status              finding_status              NOT NULL DEFAULT 'open',
    issue_type          TEXT                        NOT NULL, -- e.g., "missing_mx", "missing_www", "missing_soa"
    missing_record_type TEXT                        NOT NULL,
    details             TEXT,
    created_at          TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- HISTORY TABLES

-- 1. Dangling CNAME History
CREATE TABLE dangling_cname_findings_history
(
    id                SERIAL PRIMARY KEY,
    record_id         INT REFERENCES dangling_cname_findings (id) ON DELETE CASCADE,
    severity          finding_severity NOT NULL,
    status            finding_status   NOT NULL,
    target_domain     TEXT             NOT NULL,
    service_provider  TEXT,
    takeover_possible BOOLEAN          NOT NULL,
    details           TEXT,
    change_type       TEXT             NOT NULL, -- 'created', 'updated', 'deleted'
    changed_at        TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 2. Zone Transfer History
CREATE TABLE zone_transfer_findings_history
(
    id                     SERIAL PRIMARY KEY,
    record_id              INT REFERENCES zone_transfer_findings (id) ON DELETE CASCADE,
    severity               finding_severity NOT NULL,
    status                 finding_status   NOT NULL,
    nameserver             TEXT             NOT NULL,
    zone_transfer_possible BOOLEAN          NOT NULL,
    transfer_type          transfer_type    NOT NULL,
    details                TEXT,
    change_type            TEXT             NOT NULL,
    changed_at             TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 3. DNSSEC History
CREATE TABLE dnssec_findings_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES dnssec_findings (id) ON DELETE CASCADE,
    severity    finding_severity NOT NULL,
    status      finding_status   NOT NULL,
    issue_type  TEXT             NOT NULL,
    details     TEXT,
    change_type TEXT             NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 4. SPF History
CREATE TABLE spf_findings_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES spf_findings (id) ON DELETE CASCADE,
    severity    finding_severity NOT NULL,
    status      finding_status   NOT NULL,
    issue_type  TEXT             NOT NULL,
    spf_value   TEXT,
    details     TEXT,
    change_type TEXT             NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 5. DKIM History
CREATE TABLE dkim_findings_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES dkim_findings (id) ON DELETE CASCADE,
    severity    finding_severity NOT NULL,
    status      finding_status   NOT NULL,
    selector    TEXT,
    issue_type  TEXT             NOT NULL,
    details     TEXT,
    change_type TEXT             NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 6. DMARC History
CREATE TABLE dmarc_findings_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES dmarc_findings (id) ON DELETE CASCADE,
    severity    finding_severity NOT NULL,
    status      finding_status   NOT NULL,
    policy      TEXT,
    issue_type  TEXT             NOT NULL,
    details     TEXT,
    change_type TEXT             NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 7. Open Port History
CREATE TABLE open_port_findings_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES open_port_findings (id) ON DELETE CASCADE,
    severity    finding_severity NOT NULL,
    status      finding_status   NOT NULL,
    ip_address  TEXT             NOT NULL,
    port        INT              NOT NULL,
    service     TEXT,
    issue_type  TEXT             NOT NULL,
    details     TEXT,
    change_type TEXT             NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 8. CNAME Redirection History
CREATE TABLE cname_redirection_findings_history
(
    id           SERIAL PRIMARY KEY,
    record_id    INT REFERENCES cname_redirection_findings (id) ON DELETE CASCADE,
    severity     finding_severity NOT NULL,
    status       finding_status   NOT NULL,
    issue_type   TEXT             NOT NULL,
    chain_length INT,
    details      TEXT,
    change_type  TEXT             NOT NULL,
    changed_at   TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 9. NS Configuration History
CREATE TABLE ns_configuration_findings_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES ns_configuration_findings (id) ON DELETE CASCADE,
    severity    finding_severity NOT NULL,
    status      finding_status   NOT NULL,
    issue_type  TEXT             NOT NULL,
    nameserver  TEXT             NOT NULL,
    details     TEXT,
    change_type TEXT             NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 10. CAA Configuration History
CREATE TABLE caa_configuration_findings_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES caa_configuration_findings (id) ON DELETE CASCADE,
    severity    finding_severity NOT NULL,
    status      finding_status   NOT NULL,
    issue_type  TEXT             NOT NULL,
    details     TEXT,
    change_type TEXT             NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 11. DNS Resolution Consistency History
CREATE TABLE dns_resolution_consistency_findings_history
(
    id               SERIAL PRIMARY KEY,
    record_id        INT REFERENCES dns_resolution_consistency_findings (id) ON DELETE CASCADE,
    severity         finding_severity NOT NULL,
    status           finding_status   NOT NULL,
    record_type      TEXT             NOT NULL,
    resolver1        TEXT             NOT NULL,
    resolver1_result TEXT,
    resolver2        TEXT             NOT NULL,
    resolver2_result TEXT,
    details          TEXT,
    change_type      TEXT             NOT NULL,
    changed_at       TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 12. DNS Resolution Latency History
CREATE TABLE dns_resolution_latency_findings_history
(
    id           SERIAL PRIMARY KEY,
    record_id    INT REFERENCES dns_resolution_latency_findings (id) ON DELETE CASCADE,
    severity     finding_severity NOT NULL,
    status       finding_status   NOT NULL,
    record_type  TEXT             NOT NULL,
    resolver     TEXT             NOT NULL,
    latency_ms   INT              NOT NULL,
    threshold_ms INT              NOT NULL,
    details      TEXT,
    change_type  TEXT             NOT NULL,
    changed_at   TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 13. Nameserver Reachability History
CREATE TABLE nameserver_reachability_findings_history
(
    id               SERIAL PRIMARY KEY,
    record_id        INT REFERENCES nameserver_reachability_findings (id) ON DELETE CASCADE,
    severity         finding_severity NOT NULL,
    status           finding_status   NOT NULL,
    nameserver       TEXT             NOT NULL,
    issue_type       TEXT             NOT NULL,
    response_time_ms INT,
    details          TEXT,
    change_type      TEXT             NOT NULL,
    changed_at       TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 14. DNSSEC Compliance History
CREATE TABLE dnssec_compliance_findings_history
(
    id            SERIAL PRIMARY KEY,
    record_id     INT REFERENCES dnssec_compliance_findings (id) ON DELETE CASCADE,
    severity      finding_severity NOT NULL,
    status        finding_status   NOT NULL,
    issue_type    TEXT             NOT NULL,
    standard_name TEXT,
    details       TEXT,
    change_type   TEXT             NOT NULL,
    changed_at    TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 15. Email Auth Compliance History
CREATE TABLE email_auth_compliance_findings_history
(
    id            SERIAL PRIMARY KEY,
    record_id     INT REFERENCES email_auth_compliance_findings (id) ON DELETE CASCADE,
    severity      finding_severity NOT NULL,
    status        finding_status   NOT NULL,
    auth_type     TEXT             NOT NULL,
    issue_type    TEXT             NOT NULL,
    standard_name TEXT,
    details       TEXT,
    change_type   TEXT             NOT NULL,
    changed_at    TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 16. CAA Compliance History
CREATE TABLE caa_compliance_findings_history
(
    id            SERIAL PRIMARY KEY,
    record_id     INT REFERENCES caa_compliance_findings (id) ON DELETE CASCADE,
    severity      finding_severity NOT NULL,
    status        finding_status   NOT NULL,
    issue_type    TEXT             NOT NULL,
    standard_name TEXT,
    details       TEXT,
    change_type   TEXT             NOT NULL,
    changed_at    TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 18. Nameserver Redundancy History
CREATE TABLE nameserver_redundancy_findings_history
(
    id                SERIAL PRIMARY KEY,
    record_id         INT REFERENCES nameserver_redundancy_findings (id) ON DELETE CASCADE,
    severity          finding_severity NOT NULL,
    status            finding_status   NOT NULL,
    issue_type        TEXT             NOT NULL,
    nameserver_count  INT              NOT NULL,
    recommended_count INT              NOT NULL,
    details           TEXT,
    change_type       TEXT             NOT NULL,
    changed_at        TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 19. Minimum Record Set History
CREATE TABLE minimum_record_set_findings_history
(
    id                  SERIAL PRIMARY KEY,
    record_id           INT REFERENCES minimum_record_set_findings (id) ON DELETE CASCADE,
    severity            finding_severity NOT NULL,
    status              finding_status   NOT NULL,
    issue_type          TEXT             NOT NULL,
    missing_record_type TEXT             NOT NULL,
    details             TEXT,
    change_type         TEXT             NOT NULL,
    changed_at          TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- 1. Dangling CNAME Trigger Function
CREATE OR REPLACE FUNCTION record_dangling_cname_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO dangling_cname_findings_history (record_id, severity, status, target_domain, service_provider,
                                                     takeover_possible, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.target_domain, NEW.service_provider,
                NEW.takeover_possible, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.target_domain IS DISTINCT FROM NEW.target_domain OR
            OLD.service_provider IS DISTINCT FROM NEW.service_provider OR
            OLD.takeover_possible IS DISTINCT FROM NEW.takeover_possible OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO dangling_cname_findings_history (record_id, severity, status, target_domain, service_provider,
                                                         takeover_possible, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.target_domain, NEW.service_provider,
                    NEW.takeover_possible, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO dangling_cname_findings_history (record_id, severity, status, target_domain, service_provider,
                                                     takeover_possible, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.target_domain, OLD.service_provider,
                OLD.takeover_possible, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- 2. Zone Transfer Trigger Function
CREATE OR REPLACE FUNCTION record_zone_transfer_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO zone_transfer_findings_history (record_id, severity, status, nameserver, zone_transfer_possible,
                                                    transfer_type, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.nameserver, NEW.zone_transfer_possible,
                NEW.transfer_type, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.nameserver IS DISTINCT FROM NEW.nameserver OR
            OLD.zone_transfer_possible IS DISTINCT FROM NEW.zone_transfer_possible OR
            OLD.transfer_type IS DISTINCT FROM NEW.transfer_type OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO zone_transfer_findings_history (record_id, severity, status, nameserver, zone_transfer_possible,
                                                        transfer_type, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.nameserver, NEW.zone_transfer_possible,
                    NEW.transfer_type, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO zone_transfer_findings_history (record_id, severity, status, nameserver, zone_transfer_possible,
                                                    transfer_type, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.nameserver, OLD.zone_transfer_possible,
                OLD.transfer_type, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- 3. DNSSEC Findings
CREATE OR REPLACE FUNCTION record_dnssec_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO dnssec_findings_history (record_id, severity, status, issue_type, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO dnssec_findings_history (record_id, severity, status, issue_type, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO dnssec_findings_history (record_id, severity, status, issue_type, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.issue_type, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER dnssec_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON dnssec_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dnssec_history();

CREATE TRIGGER dnssec_findings_history_delete_trigger
    BEFORE DELETE
    ON dnssec_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dnssec_history();

-- 4. SPF Findings
CREATE OR REPLACE FUNCTION record_spf_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO spf_findings_history (record_id, severity, status, issue_type, spf_value, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.spf_value, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.spf_value IS DISTINCT FROM NEW.spf_value OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO spf_findings_history (record_id, severity, status, issue_type, spf_value, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.spf_value, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO spf_findings_history (record_id, severity, status, issue_type, spf_value, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.issue_type, OLD.spf_value, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER spf_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON spf_findings
    FOR EACH ROW
EXECUTE FUNCTION record_spf_history();

CREATE TRIGGER spf_findings_history_delete_trigger
    BEFORE DELETE
    ON spf_findings
    FOR EACH ROW
EXECUTE FUNCTION record_spf_history();
-- 5. DKIM Trigger Function
CREATE OR REPLACE FUNCTION record_dkim_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO dkim_findings_history (record_id, severity, status, selector, issue_type, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.selector, NEW.issue_type, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.selector IS DISTINCT FROM NEW.selector OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO dkim_findings_history (record_id, severity, status, selector, issue_type, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.selector, NEW.issue_type, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO dkim_findings_history (record_id, severity, status, selector, issue_type, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.selector, OLD.issue_type, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER dkim_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON dkim_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dkim_history();

CREATE TRIGGER dkim_findings_history_delete_trigger
    BEFORE DELETE
    ON dkim_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dkim_history();

-- 6. DMARC Trigger Function
CREATE OR REPLACE FUNCTION record_dmarc_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO dmarc_findings_history (record_id, severity, status, policy, issue_type, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.policy, NEW.issue_type, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.policy IS DISTINCT FROM NEW.policy OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO dmarc_findings_history (record_id, severity, status, policy, issue_type, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.policy, NEW.issue_type, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO dmarc_findings_history (record_id, severity, status, policy, issue_type, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.policy, OLD.issue_type, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER dmarc_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON dmarc_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dmarc_history();

CREATE TRIGGER dmarc_findings_history_delete_trigger
    BEFORE DELETE
    ON dmarc_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dmarc_history();

-- 7. Open Port Trigger Function
CREATE OR REPLACE FUNCTION record_open_port_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO open_port_findings_history (record_id, severity, status, ip_address, port, service, issue_type,
                                                details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.ip_address, NEW.port, NEW.service,
                NEW.issue_type, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.ip_address IS DISTINCT FROM NEW.ip_address OR
            OLD.port IS DISTINCT FROM NEW.port OR
            OLD.service IS DISTINCT FROM NEW.service OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO open_port_findings_history (record_id, severity, status, ip_address, port, service, issue_type,
                                                    details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.ip_address, NEW.port, NEW.service,
                    NEW.issue_type, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO open_port_findings_history (record_id, severity, status, ip_address, port, service, issue_type,
                                                details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.ip_address, OLD.port, OLD.service,
                OLD.issue_type, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER open_port_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON open_port_findings
    FOR EACH ROW
EXECUTE FUNCTION record_open_port_history();

CREATE TRIGGER open_port_findings_history_delete_trigger
    BEFORE DELETE
    ON open_port_findings
    FOR EACH ROW
EXECUTE FUNCTION record_open_port_history();

-- 8. CNAME Redirection Trigger Function
CREATE OR REPLACE FUNCTION record_cname_redirection_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO cname_redirection_findings_history (record_id, severity, status, issue_type, chain_length, details,
                                                        change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.chain_length, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.chain_length IS DISTINCT FROM NEW.chain_length OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO cname_redirection_findings_history (record_id, severity, status, issue_type, chain_length,
                                                            details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.chain_length, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO cname_redirection_findings_history (record_id, severity, status, issue_type, chain_length, details,
                                                        change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.issue_type, OLD.chain_length, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER cname_redirection_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON cname_redirection_findings
    FOR EACH ROW
EXECUTE FUNCTION record_cname_redirection_history();

CREATE TRIGGER cname_redirection_findings_history_delete_trigger
    BEFORE DELETE
    ON cname_redirection_findings
    FOR EACH ROW
EXECUTE FUNCTION record_cname_redirection_history();

-- 9. NS Configuration Trigger Function
CREATE OR REPLACE FUNCTION record_ns_configuration_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO ns_configuration_findings_history (record_id, severity, status, issue_type, nameserver, details,
                                                       change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.nameserver, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.nameserver IS DISTINCT FROM NEW.nameserver OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO ns_configuration_findings_history (record_id, severity, status, issue_type, nameserver, details,
                                                           change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.nameserver, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO ns_configuration_findings_history (record_id, severity, status, issue_type, nameserver, details,
                                                       change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.issue_type, OLD.nameserver, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ns_configuration_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON ns_configuration_findings
    FOR EACH ROW
EXECUTE FUNCTION record_ns_configuration_history();

CREATE TRIGGER ns_configuration_findings_history_delete_trigger
    BEFORE DELETE
    ON ns_configuration_findings
    FOR EACH ROW
EXECUTE FUNCTION record_ns_configuration_history();

-- 10. CAA Configuration Trigger Function
CREATE OR REPLACE FUNCTION record_caa_configuration_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO caa_configuration_findings_history (record_id, severity, status, issue_type, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO caa_configuration_findings_history (record_id, severity, status, issue_type, details,
                                                            change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO caa_configuration_findings_history (record_id, severity, status, issue_type, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.issue_type, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER caa_configuration_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON caa_configuration_findings
    FOR EACH ROW
EXECUTE FUNCTION record_caa_configuration_history();

CREATE TRIGGER caa_configuration_findings_history_delete_trigger
    BEFORE DELETE
    ON caa_configuration_findings
    FOR EACH ROW
EXECUTE FUNCTION record_caa_configuration_history();
-- 11. DNS Resolution Consistency Trigger Function
CREATE OR REPLACE FUNCTION record_dns_resolution_consistency_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO dns_resolution_consistency_findings_history (record_id, severity, status, record_type, resolver1,
                                                                 resolver1_result,
                                                                 resolver2, resolver2_result, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.record_type, NEW.resolver1, NEW.resolver1_result,
                NEW.resolver2, NEW.resolver2_result, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.record_type IS DISTINCT FROM NEW.record_type OR
            OLD.resolver1 IS DISTINCT FROM NEW.resolver1 OR
            OLD.resolver1_result IS DISTINCT FROM NEW.resolver1_result OR
            OLD.resolver2 IS DISTINCT FROM NEW.resolver2 OR
            OLD.resolver2_result IS DISTINCT FROM NEW.resolver2_result OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO dns_resolution_consistency_findings_history (record_id, severity, status, record_type,
                                                                     resolver1, resolver1_result,
                                                                     resolver2, resolver2_result, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.record_type, NEW.resolver1, NEW.resolver1_result,
                    NEW.resolver2, NEW.resolver2_result, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO dns_resolution_consistency_findings_history (record_id, severity, status, record_type, resolver1,
                                                                 resolver1_result,
                                                                 resolver2, resolver2_result, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.record_type, OLD.resolver1, OLD.resolver1_result,
                OLD.resolver2, OLD.resolver2_result, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER dns_resolution_consistency_findings_history_in_update_trigger
    AFTER INSERT OR UPDATE
    ON dns_resolution_consistency_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dns_resolution_consistency_history();

CREATE TRIGGER dns_resolution_consistency_findings_history_delete_trigger
    BEFORE DELETE
    ON dns_resolution_consistency_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dns_resolution_consistency_history();

-- 12. DNS Resolution Latency Trigger Function
CREATE OR REPLACE FUNCTION record_dns_resolution_latency_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO dns_resolution_latency_findings_history (record_id, severity, status, record_type, resolver,
                                                             latency_ms, threshold_ms, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.record_type, NEW.resolver,
                NEW.latency_ms, NEW.threshold_ms, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.record_type IS DISTINCT FROM NEW.record_type OR
            OLD.resolver IS DISTINCT FROM NEW.resolver OR
            OLD.latency_ms IS DISTINCT FROM NEW.latency_ms OR
            OLD.threshold_ms IS DISTINCT FROM NEW.threshold_ms OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO dns_resolution_latency_findings_history (record_id, severity, status, record_type, resolver,
                                                                 latency_ms, threshold_ms, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.record_type, NEW.resolver,
                    NEW.latency_ms, NEW.threshold_ms, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO dns_resolution_latency_findings_history (record_id, severity, status, record_type, resolver,
                                                             latency_ms, threshold_ms, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.record_type, OLD.resolver,
                OLD.latency_ms, OLD.threshold_ms, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER dns_resolution_latency_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON dns_resolution_latency_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dns_resolution_latency_history();

CREATE TRIGGER dns_resolution_latency_findings_history_delete_trigger
    BEFORE DELETE
    ON dns_resolution_latency_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dns_resolution_latency_history();

-- 13. Nameserver Reachability Trigger Function
CREATE OR REPLACE FUNCTION record_nameserver_reachability_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO nameserver_reachability_findings_history (record_id, severity, status, nameserver, issue_type,
                                                              response_time_ms, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.nameserver, NEW.issue_type,
                NEW.response_time_ms, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.nameserver IS DISTINCT FROM NEW.nameserver OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.response_time_ms IS DISTINCT FROM NEW.response_time_ms OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO nameserver_reachability_findings_history (record_id, severity, status, nameserver, issue_type,
                                                                  response_time_ms, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.nameserver, NEW.issue_type,
                    NEW.response_time_ms, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO nameserver_reachability_findings_history (record_id, severity, status, nameserver, issue_type,
                                                              response_time_ms, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.nameserver, OLD.issue_type,
                OLD.response_time_ms, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER nameserver_reachability_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON nameserver_reachability_findings
    FOR EACH ROW
EXECUTE FUNCTION record_nameserver_reachability_history();

CREATE TRIGGER nameserver_reachability_findings_history_delete_trigger
    BEFORE DELETE
    ON nameserver_reachability_findings
    FOR EACH ROW
EXECUTE FUNCTION record_nameserver_reachability_history();

-- 14. DNSSEC Compliance Trigger Function
CREATE OR REPLACE FUNCTION record_dnssec_compliance_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO dnssec_compliance_findings_history (record_id, severity, status, issue_type, standard_name, details,
                                                        change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.standard_name, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.standard_name IS DISTINCT FROM NEW.standard_name OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO dnssec_compliance_findings_history (record_id, severity, status, issue_type, standard_name,
                                                            details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.standard_name, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO dnssec_compliance_findings_history (record_id, severity, status, issue_type, standard_name, details,
                                                        change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.issue_type, OLD.standard_name, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER dnssec_compliance_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON dnssec_compliance_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dnssec_compliance_history();

CREATE TRIGGER dnssec_compliance_findings_history_delete_trigger
    BEFORE DELETE
    ON dnssec_compliance_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dnssec_compliance_history();

-- 15. Email Auth Compliance Trigger Function
CREATE OR REPLACE FUNCTION record_email_auth_compliance_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO email_auth_compliance_findings_history (record_id, severity, status, auth_type, issue_type,
                                                            standard_name, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.auth_type, NEW.issue_type,
                NEW.standard_name, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.auth_type IS DISTINCT FROM NEW.auth_type OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.standard_name IS DISTINCT FROM NEW.standard_name OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO email_auth_compliance_findings_history (record_id, severity, status, auth_type, issue_type,
                                                                standard_name, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.auth_type, NEW.issue_type,
                    NEW.standard_name, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO email_auth_compliance_findings_history (record_id, severity, status, auth_type, issue_type,
                                                            standard_name, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.auth_type, OLD.issue_type,
                OLD.standard_name, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER email_auth_compliance_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON email_auth_compliance_findings
    FOR EACH ROW
EXECUTE FUNCTION record_email_auth_compliance_history();

CREATE TRIGGER email_auth_compliance_findings_history_delete_trigger
    BEFORE DELETE
    ON email_auth_compliance_findings
    FOR EACH ROW
EXECUTE FUNCTION record_email_auth_compliance_history();

-- 16. CAA Compliance Trigger Function
CREATE OR REPLACE FUNCTION record_caa_compliance_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO caa_compliance_findings_history (record_id, severity, status, issue_type, standard_name, details,
                                                     change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.standard_name, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.standard_name IS DISTINCT FROM NEW.standard_name OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO caa_compliance_findings_history (record_id, severity, status, issue_type, standard_name,
                                                         details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.standard_name, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO caa_compliance_findings_history (record_id, severity, status, issue_type, standard_name, details,
                                                     change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.issue_type, OLD.standard_name, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER caa_compliance_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON caa_compliance_findings
    FOR EACH ROW
EXECUTE FUNCTION record_caa_compliance_history();

CREATE TRIGGER caa_compliance_findings_history_delete_trigger
    BEFORE DELETE
    ON caa_compliance_findings
    FOR EACH ROW
EXECUTE FUNCTION record_caa_compliance_history();

-- 18. Nameserver Redundancy Trigger Function
CREATE OR REPLACE FUNCTION record_nameserver_redundancy_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO nameserver_redundancy_findings_history (record_id, severity, status, issue_type, nameserver_count,
                                                            recommended_count, details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.nameserver_count,
                NEW.recommended_count, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.nameserver_count IS DISTINCT FROM NEW.nameserver_count OR
            OLD.recommended_count IS DISTINCT FROM NEW.recommended_count OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO nameserver_redundancy_findings_history (record_id, severity, status, issue_type,
                                                                nameserver_count, recommended_count, details,
                                                                change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.nameserver_count,
                    NEW.recommended_count, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO nameserver_redundancy_findings_history (record_id, severity, status, issue_type, nameserver_count,
                                                            recommended_count, details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.issue_type, OLD.nameserver_count,
                OLD.recommended_count, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER nameserver_redundancy_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON nameserver_redundancy_findings
    FOR EACH ROW
EXECUTE FUNCTION record_nameserver_redundancy_history();

CREATE TRIGGER nameserver_redundancy_findings_history_delete_trigger
    BEFORE DELETE
    ON nameserver_redundancy_findings
    FOR EACH ROW
EXECUTE FUNCTION record_nameserver_redundancy_history();

-- 19. Minimum Record Set Trigger Function
CREATE OR REPLACE FUNCTION record_minimum_record_set_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO minimum_record_set_findings_history (record_id, severity, status, issue_type, missing_record_type,
                                                         details, change_type)
        VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.missing_record_type, NEW.details, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.severity IS DISTINCT FROM NEW.severity OR
            OLD.status IS DISTINCT FROM NEW.status OR
            OLD.issue_type IS DISTINCT FROM NEW.issue_type OR
            OLD.missing_record_type IS DISTINCT FROM NEW.missing_record_type OR
            OLD.details IS DISTINCT FROM NEW.details) THEN
            INSERT INTO minimum_record_set_findings_history (record_id, severity, status, issue_type,
                                                             missing_record_type, details, change_type)
            VALUES (NEW.id, NEW.severity, NEW.status, NEW.issue_type, NEW.missing_record_type, NEW.details, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO minimum_record_set_findings_history (record_id, severity, status, issue_type, missing_record_type,
                                                         details, change_type)
        VALUES (OLD.id, OLD.severity, OLD.status, OLD.issue_type, OLD.missing_record_type, OLD.details, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER minimum_record_set_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON minimum_record_set_findings
    FOR EACH ROW
EXECUTE FUNCTION record_minimum_record_set_history();

CREATE TRIGGER minimum_record_set_findings_history_delete_trigger
    BEFORE DELETE
    ON minimum_record_set_findings
    FOR EACH ROW
EXECUTE FUNCTION record_minimum_record_set_history();

-- Updated_at triggers for all main tables
CREATE TRIGGER trigger_updated_at_dangling_cname
    BEFORE UPDATE
    ON dangling_cname_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_zone_transfer
    BEFORE UPDATE
    ON zone_transfer_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_dnssec
    BEFORE UPDATE
    ON dnssec_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_spf
    BEFORE UPDATE
    ON spf_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_dkim
    BEFORE UPDATE
    ON dkim_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_dmarc
    BEFORE UPDATE
    ON dmarc_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_open_port
    BEFORE UPDATE
    ON open_port_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_cname_redirection
    BEFORE UPDATE
    ON cname_redirection_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_ns_config
    BEFORE UPDATE
    ON ns_configuration_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_caa_config
    BEFORE UPDATE
    ON caa_configuration_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_dns_consistency
    BEFORE UPDATE
    ON dns_resolution_consistency_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_dns_latency
    BEFORE UPDATE
    ON dns_resolution_latency_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_ns_reachability
    BEFORE UPDATE
    ON nameserver_reachability_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_dnssec_compliance
    BEFORE UPDATE
    ON dnssec_compliance_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_email_auth
    BEFORE UPDATE
    ON email_auth_compliance_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_caa_compliance
    BEFORE UPDATE
    ON caa_compliance_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_ns_redundancy
    BEFORE UPDATE
    ON nameserver_redundancy_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

CREATE TRIGGER trigger_updated_at_min_record_set
    BEFORE UPDATE
    ON minimum_record_set_findings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

-- History triggers for insert/update
CREATE TRIGGER dangling_cname_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON dangling_cname_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dangling_cname_history();

CREATE TRIGGER dangling_cname_findings_history_delete_trigger
    BEFORE DELETE
    ON dangling_cname_findings
    FOR EACH ROW
EXECUTE FUNCTION record_dangling_cname_history();

CREATE TRIGGER zone_transfer_findings_history_insert_update_trigger
    AFTER INSERT OR UPDATE
    ON zone_transfer_findings
    FOR EACH ROW
EXECUTE FUNCTION record_zone_transfer_history();

CREATE TRIGGER zone_transfer_findings_history_delete_trigger
    BEFORE DELETE
    ON zone_transfer_findings
    FOR EACH ROW
EXECUTE FUNCTION record_zone_transfer_history();
-- Create indexes for efficient querying
CREATE INDEX idx_dangling_cname_domain_id ON dangling_cname_findings (domain_id);
CREATE INDEX idx_dangling_cname_severity ON dangling_cname_findings (severity);
CREATE INDEX idx_dangling_cname_status ON dangling_cname_findings (status);
CREATE INDEX idx_dangling_cname_target ON dangling_cname_findings (target_domain);

CREATE INDEX idx_zone_transfer_domain_id ON zone_transfer_findings (domain_id);
CREATE INDEX idx_zone_transfer_severity ON zone_transfer_findings (severity);
CREATE INDEX idx_zone_transfer_status ON zone_transfer_findings (status);
CREATE INDEX idx_zone_transfer_nameserver ON zone_transfer_findings (nameserver);

CREATE INDEX idx_dnssec_domain_id ON dnssec_findings (domain_id);
CREATE INDEX idx_dnssec_severity ON dnssec_findings (severity);
CREATE INDEX idx_dnssec_status ON dnssec_findings (status);
CREATE INDEX idx_dnssec_issue_type ON dnssec_findings (issue_type);

CREATE INDEX idx_spf_domain_id ON spf_findings (domain_id);
CREATE INDEX idx_spf_severity ON spf_findings (severity);
CREATE INDEX idx_spf_status ON spf_findings (status);

CREATE INDEX idx_dkim_domain_id ON dkim_findings (domain_id);
CREATE INDEX idx_dkim_severity ON dkim_findings (severity);
CREATE INDEX idx_dkim_status ON dkim_findings (status);
CREATE INDEX idx_dkim_selector ON dkim_findings (selector);

CREATE INDEX idx_dmarc_domain_id ON dmarc_findings (domain_id);
CREATE INDEX idx_dmarc_severity ON dmarc_findings (severity);
CREATE INDEX idx_dmarc_status ON dmarc_findings (status);
CREATE INDEX idx_dmarc_policy ON dmarc_findings (policy);
CREATE INDEX idx_dmarc_issue_type ON dmarc_findings (issue_type);

CREATE INDEX idx_open_port_domain_id ON open_port_findings (domain_id);
CREATE INDEX idx_open_port_severity ON open_port_findings (severity);
CREATE INDEX idx_open_port_status ON open_port_findings (status);
CREATE INDEX idx_open_port_ip ON open_port_findings (ip_address);
CREATE INDEX idx_open_port_port ON open_port_findings (port);
CREATE INDEX idx_open_port_issue_type ON open_port_findings (issue_type);

CREATE INDEX idx_cname_redirection_domain_id ON cname_redirection_findings (domain_id);
CREATE INDEX idx_cname_redirection_severity ON cname_redirection_findings (severity);
CREATE INDEX idx_cname_redirection_status ON cname_redirection_findings (status);
CREATE INDEX idx_cname_redirection_issue_type ON cname_redirection_findings (issue_type);

CREATE INDEX idx_ns_config_domain_id ON ns_configuration_findings (domain_id);
CREATE INDEX idx_ns_config_severity ON ns_configuration_findings (severity);
CREATE INDEX idx_ns_config_status ON ns_configuration_findings (status);
CREATE INDEX idx_ns_config_issue_type ON ns_configuration_findings (issue_type);
CREATE INDEX idx_ns_config_nameserver ON ns_configuration_findings (nameserver);

CREATE INDEX idx_caa_config_domain_id ON caa_configuration_findings (domain_id);
CREATE INDEX idx_caa_config_severity ON caa_configuration_findings (severity);
CREATE INDEX idx_caa_config_status ON caa_configuration_findings (status);

CREATE INDEX idx_dns_consistency_domain_id ON dns_resolution_consistency_findings (domain_id);
CREATE INDEX idx_dns_consistency_severity ON dns_resolution_consistency_findings (severity);
CREATE INDEX idx_dns_consistency_status ON dns_resolution_consistency_findings (status);
CREATE INDEX idx_dns_consistency_record_type ON dns_resolution_consistency_findings (record_type);

CREATE INDEX idx_dns_latency_domain_id ON dns_resolution_latency_findings (domain_id);
CREATE INDEX idx_dns_latency_severity ON dns_resolution_latency_findings (severity);
CREATE INDEX idx_dns_latency_status ON dns_resolution_latency_findings (status);
CREATE INDEX idx_dns_latency_record_type ON dns_resolution_latency_findings (record_type);
CREATE INDEX idx_dns_latency_resolver ON dns_resolution_latency_findings (resolver);

CREATE INDEX idx_ns_reachability_domain_id ON nameserver_reachability_findings (domain_id);
CREATE INDEX idx_ns_reachability_severity ON nameserver_reachability_findings (severity);
CREATE INDEX idx_ns_reachability_status ON nameserver_reachability_findings (status);
CREATE INDEX idx_ns_reachability_nameserver ON nameserver_reachability_findings (nameserver);
CREATE INDEX idx_ns_reachability_issue_type ON nameserver_reachability_findings (issue_type);

CREATE INDEX idx_dnssec_compliance_domain_id ON dnssec_compliance_findings (domain_id);
CREATE INDEX idx_dnssec_compliance_severity ON dnssec_compliance_findings (severity);
CREATE INDEX idx_dnssec_compliance_status ON dnssec_compliance_findings (status);
CREATE INDEX idx_dnssec_compliance_issue_type ON dnssec_compliance_findings (issue_type);

CREATE INDEX idx_email_auth_domain_id ON email_auth_compliance_findings (domain_id);
CREATE INDEX idx_email_auth_severity ON email_auth_compliance_findings (severity);
CREATE INDEX idx_email_auth_status ON email_auth_compliance_findings (status);
CREATE INDEX idx_email_auth_type ON email_auth_compliance_findings (auth_type);
CREATE INDEX idx_email_auth_issue_type ON email_auth_compliance_findings (issue_type);

CREATE INDEX idx_caa_compliance_domain_id ON caa_compliance_findings (domain_id);
CREATE INDEX idx_caa_compliance_severity ON caa_compliance_findings (severity);
CREATE INDEX idx_caa_compliance_status ON caa_compliance_findings (status);
CREATE INDEX idx_caa_compliance_issue_type ON caa_compliance_findings (issue_type);

CREATE INDEX idx_ns_redundancy_domain_id ON nameserver_redundancy_findings (domain_id);
CREATE INDEX idx_ns_redundancy_severity ON nameserver_redundancy_findings (severity);
CREATE INDEX idx_ns_redundancy_status ON nameserver_redundancy_findings (status);
CREATE INDEX idx_ns_redundancy_issue_type ON nameserver_redundancy_findings (issue_type);

CREATE INDEX idx_min_record_set_domain_id ON minimum_record_set_findings (domain_id);
CREATE INDEX idx_min_record_set_severity ON minimum_record_set_findings (severity);
CREATE INDEX idx_min_record_set_status ON minimum_record_set_findings (status);
CREATE INDEX idx_min_record_set_issue_type ON minimum_record_set_findings (issue_type);
CREATE INDEX idx_min_record_set_missing_type ON minimum_record_set_findings (missing_record_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- First drop all triggers
DROP TRIGGER IF EXISTS dangling_cname_findings_history_insert_update_trigger ON dangling_cname_findings;
DROP TRIGGER IF EXISTS dangling_cname_findings_history_delete_trigger ON dangling_cname_findings;
DROP TRIGGER IF EXISTS zone_transfer_findings_history_insert_update_trigger ON zone_transfer_findings;
DROP TRIGGER IF EXISTS zone_transfer_findings_history_delete_trigger ON zone_transfer_findings;
DROP TRIGGER IF EXISTS dnssec_findings_history_insert_update_trigger ON dnssec_findings;
DROP TRIGGER IF EXISTS dnssec_findings_history_delete_trigger ON dnssec_findings;
DROP TRIGGER IF EXISTS spf_findings_history_insert_update_trigger ON spf_findings;
DROP TRIGGER IF EXISTS spf_findings_history_delete_trigger ON spf_findings;
DROP TRIGGER IF EXISTS dkim_findings_history_insert_update_trigger ON dkim_findings;
DROP TRIGGER IF EXISTS dkim_findings_history_delete_trigger ON dkim_findings;
DROP TRIGGER IF EXISTS dmarc_findings_history_insert_update_trigger ON dmarc_findings;
DROP TRIGGER IF EXISTS dmarc_findings_history_delete_trigger ON dmarc_findings;
DROP TRIGGER IF EXISTS open_port_findings_history_insert_update_trigger ON open_port_findings;
DROP TRIGGER IF EXISTS open_port_findings_history_delete_trigger ON open_port_findings;
DROP TRIGGER IF EXISTS cname_redirection_findings_history_insert_update_trigger ON cname_redirection_findings;
DROP TRIGGER IF EXISTS cname_redirection_findings_history_delete_trigger ON cname_redirection_findings;
DROP TRIGGER IF EXISTS ns_configuration_findings_history_insert_update_trigger ON ns_configuration_findings;
DROP TRIGGER IF EXISTS ns_configuration_findings_history_delete_trigger ON ns_configuration_findings;
DROP TRIGGER IF EXISTS caa_configuration_findings_history_insert_update_trigger ON caa_configuration_findings;
DROP TRIGGER IF EXISTS caa_configuration_findings_history_delete_trigger ON caa_configuration_findings;
DROP TRIGGER IF EXISTS dns_resolution_consistency_findings_history_in_update_trigger ON dns_resolution_consistency_findings;
DROP TRIGGER IF EXISTS dns_resolution_consistency_findings_history_delete_trigger ON dns_resolution_consistency_findings;
DROP TRIGGER IF EXISTS dns_resolution_latency_findings_history_insert_update_trigger ON dns_resolution_latency_findings;
DROP TRIGGER IF EXISTS dns_resolution_latency_findings_history_delete_trigger ON dns_resolution_latency_findings;
DROP TRIGGER IF EXISTS nameserver_reachability_findings_history_insert_update_trigger ON nameserver_reachability_findings;
DROP TRIGGER IF EXISTS nameserver_reachability_findings_history_delete_trigger ON nameserver_reachability_findings;
DROP TRIGGER IF EXISTS dnssec_compliance_findings_history_insert_update_trigger ON dnssec_compliance_findings;
DROP TRIGGER IF EXISTS dnssec_compliance_findings_history_delete_trigger ON dnssec_compliance_findings;
DROP TRIGGER IF EXISTS email_auth_compliance_findings_history_insert_update_trigger ON email_auth_compliance_findings;
DROP TRIGGER IF EXISTS email_auth_compliance_findings_history_delete_trigger ON email_auth_compliance_findings;
DROP TRIGGER IF EXISTS caa_compliance_findings_history_insert_update_trigger ON caa_compliance_findings;
DROP TRIGGER IF EXISTS caa_compliance_findings_history_delete_trigger ON caa_compliance_findings;
DROP TRIGGER IF EXISTS nameserver_redundancy_findings_history_insert_update_trigger ON nameserver_redundancy_findings;
DROP TRIGGER IF EXISTS nameserver_redundancy_findings_history_delete_trigger ON nameserver_redundancy_findings;
DROP TRIGGER IF EXISTS minimum_record_set_findings_history_insert_update_trigger ON minimum_record_set_findings;
DROP TRIGGER IF EXISTS minimum_record_set_findings_history_delete_trigger ON minimum_record_set_findings;

-- Drop updated_at triggers
DROP TRIGGER IF EXISTS trigger_updated_at_dangling_cname ON dangling_cname_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_zone_transfer ON zone_transfer_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_dnssec ON dnssec_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_spf ON spf_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_dkim ON dkim_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_dmarc ON dmarc_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_open_port ON open_port_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_cname_redirection ON cname_redirection_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_ns_config ON ns_configuration_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_caa_config ON caa_configuration_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_dns_consistency ON dns_resolution_consistency_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_dns_latency ON dns_resolution_latency_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_ns_reachability ON nameserver_reachability_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_dnssec_compliance ON dnssec_compliance_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_email_auth ON email_auth_compliance_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_caa_compliance ON caa_compliance_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_ns_redundancy ON nameserver_redundancy_findings;
DROP TRIGGER IF EXISTS trigger_updated_at_min_record_set ON minimum_record_set_findings;

-- Drop all trigger functions
DROP FUNCTION IF EXISTS record_dangling_cname_history();
DROP FUNCTION IF EXISTS record_zone_transfer_history();
DROP FUNCTION IF EXISTS record_dnssec_history();
DROP FUNCTION IF EXISTS record_spf_history();
DROP FUNCTION IF EXISTS record_dkim_history();
DROP FUNCTION IF EXISTS record_dmarc_history();
DROP FUNCTION IF EXISTS record_open_port_history();
DROP FUNCTION IF EXISTS record_cname_redirection_history();
DROP FUNCTION IF EXISTS record_ns_configuration_history();
DROP FUNCTION IF EXISTS record_caa_configuration_history();
DROP FUNCTION IF EXISTS record_dns_resolution_consistency_history();
DROP FUNCTION IF EXISTS record_dns_resolution_latency_history();
DROP FUNCTION IF EXISTS record_nameserver_reachability_history();
DROP FUNCTION IF EXISTS record_dnssec_compliance_history();
DROP FUNCTION IF EXISTS record_email_auth_compliance_history();
DROP FUNCTION IF EXISTS record_caa_compliance_history();
DROP FUNCTION IF EXISTS record_zone_transfer_security_history();
DROP FUNCTION IF EXISTS record_nameserver_redundancy_history();
DROP FUNCTION IF EXISTS record_minimum_record_set_history();

-- Drop all indexes
DROP INDEX IF EXISTS idx_min_record_set_missing_type;
DROP INDEX IF EXISTS idx_min_record_set_issue_type;
DROP INDEX IF EXISTS idx_min_record_set_status;
DROP INDEX IF EXISTS idx_min_record_set_severity;
DROP INDEX IF EXISTS idx_min_record_set_domain_id;

DROP INDEX IF EXISTS idx_ns_redundancy_issue_type;
DROP INDEX IF EXISTS idx_ns_redundancy_status;
DROP INDEX IF EXISTS idx_ns_redundancy_severity;
DROP INDEX IF EXISTS idx_ns_redundancy_domain_id;

DROP INDEX IF EXISTS idx_zone_transfer_security_nameserver;
DROP INDEX IF EXISTS idx_zone_transfer_security_issue_type;
DROP INDEX IF EXISTS idx_zone_transfer_security_status;
DROP INDEX IF EXISTS idx_zone_transfer_security_severity;
DROP INDEX IF EXISTS idx_zone_transfer_security_domain_id;

DROP INDEX IF EXISTS idx_caa_compliance_issue_type;
DROP INDEX IF EXISTS idx_caa_compliance_status;
DROP INDEX IF EXISTS idx_caa_compliance_severity;
DROP INDEX IF EXISTS idx_caa_compliance_domain_id;

DROP INDEX IF EXISTS idx_email_auth_issue_type;
DROP INDEX IF EXISTS idx_email_auth_type;
DROP INDEX IF EXISTS idx_email_auth_status;
DROP INDEX IF EXISTS idx_email_auth_severity;
DROP INDEX IF EXISTS idx_email_auth_domain_id;

DROP INDEX IF EXISTS idx_dnssec_compliance_issue_type;
DROP INDEX IF EXISTS idx_dnssec_compliance_status;
DROP INDEX IF EXISTS idx_dnssec_compliance_severity;
DROP INDEX IF EXISTS idx_dnssec_compliance_domain_id;

DROP INDEX IF EXISTS idx_ns_reachability_issue_type;
DROP INDEX IF EXISTS idx_ns_reachability_nameserver;
DROP INDEX IF EXISTS idx_ns_reachability_status;
DROP INDEX IF EXISTS idx_ns_reachability_severity;
DROP INDEX IF EXISTS idx_ns_reachability_domain_id;

DROP INDEX IF EXISTS idx_dns_latency_resolver;
DROP INDEX IF EXISTS idx_dns_latency_record_type;
DROP INDEX IF EXISTS idx_dns_latency_status;
DROP INDEX IF EXISTS idx_dns_latency_severity;
DROP INDEX IF EXISTS idx_dns_latency_domain_id;

DROP INDEX IF EXISTS idx_dns_consistency_record_type;
DROP INDEX IF EXISTS idx_dns_consistency_status;
DROP INDEX IF EXISTS idx_dns_consistency_severity;
DROP INDEX IF EXISTS idx_dns_consistency_domain_id;

DROP INDEX IF EXISTS idx_caa_config_status;
DROP INDEX IF EXISTS idx_caa_config_severity;
DROP INDEX IF EXISTS idx_caa_config_domain_id;

DROP INDEX IF EXISTS idx_ns_config_nameserver;
DROP INDEX IF EXISTS idx_ns_config_issue_type;
DROP INDEX IF EXISTS idx_ns_config_status;
DROP INDEX IF EXISTS idx_ns_config_severity;
DROP INDEX IF EXISTS idx_ns_config_domain_id;

DROP INDEX IF EXISTS idx_cname_redirection_issue_type;
DROP INDEX IF EXISTS idx_cname_redirection_status;
DROP INDEX IF EXISTS idx_cname_redirection_severity;
DROP INDEX IF EXISTS idx_cname_redirection_domain_id;

DROP INDEX IF EXISTS idx_open_port_issue_type;
DROP INDEX IF EXISTS idx_open_port_port;
DROP INDEX IF EXISTS idx_open_port_ip;
DROP INDEX IF EXISTS idx_open_port_status;
DROP INDEX IF EXISTS idx_open_port_severity;
DROP INDEX IF EXISTS idx_open_port_domain_id;

DROP INDEX IF EXISTS idx_dmarc_issue_type;
DROP INDEX IF EXISTS idx_dmarc_policy;
DROP INDEX IF EXISTS idx_dmarc_status;
DROP INDEX IF EXISTS idx_dmarc_severity;
DROP INDEX IF EXISTS idx_dmarc_domain_id;

DROP INDEX IF EXISTS idx_dkim_selector;
DROP INDEX IF EXISTS idx_dkim_status;
DROP INDEX IF EXISTS idx_dkim_severity;
DROP INDEX IF EXISTS idx_dkim_domain_id;

DROP INDEX IF EXISTS idx_spf_status;
DROP INDEX IF EXISTS idx_spf_severity;
DROP INDEX IF EXISTS idx_spf_domain_id;

DROP INDEX IF EXISTS idx_dnssec_issue_type;
DROP INDEX IF EXISTS idx_dnssec_status;
DROP INDEX IF EXISTS idx_dnssec_severity;
DROP INDEX IF EXISTS idx_dnssec_domain_id;

DROP INDEX IF EXISTS idx_zone_transfer_nameserver;
DROP INDEX IF EXISTS idx_zone_transfer_status;
DROP INDEX IF EXISTS idx_zone_transfer_severity;
DROP INDEX IF EXISTS idx_zone_transfer_domain_id;

DROP INDEX IF EXISTS idx_dangling_cname_target;
DROP INDEX IF EXISTS idx_dangling_cname_status;
DROP INDEX IF EXISTS idx_dangling_cname_severity;
DROP INDEX IF EXISTS idx_dangling_cname_domain_id;

-- Drop all history tables
DROP TABLE IF EXISTS minimum_record_set_findings_history;
DROP TABLE IF EXISTS nameserver_redundancy_findings_history;
DROP TABLE IF EXISTS caa_compliance_findings_history;
DROP TABLE IF EXISTS email_auth_compliance_findings_history;
DROP TABLE IF EXISTS dnssec_compliance_findings_history;
DROP TABLE IF EXISTS nameserver_reachability_findings_history;
DROP TABLE IF EXISTS dns_resolution_latency_findings_history;
DROP TABLE IF EXISTS dns_resolution_consistency_findings_history;
DROP TABLE IF EXISTS caa_configuration_findings_history;
DROP TABLE IF EXISTS ns_configuration_findings_history;
DROP TABLE IF EXISTS cname_redirection_findings_history;
DROP TABLE IF EXISTS open_port_findings_history;
DROP TABLE IF EXISTS dmarc_findings_history;
DROP TABLE IF EXISTS dkim_findings_history;
DROP TABLE IF EXISTS spf_findings_history;
DROP TABLE IF EXISTS dnssec_findings_history;
DROP TABLE IF EXISTS zone_transfer_findings_history;
DROP TABLE IF EXISTS dangling_cname_findings_history;

-- Drop all main tables
DROP TABLE IF EXISTS minimum_record_set_findings;
DROP TABLE IF EXISTS nameserver_redundancy_findings;
DROP TABLE IF EXISTS caa_compliance_findings;
DROP TABLE IF EXISTS email_auth_compliance_findings;
DROP TABLE IF EXISTS dnssec_compliance_findings;
DROP TABLE IF EXISTS nameserver_reachability_findings;
DROP TABLE IF EXISTS dns_resolution_latency_findings;
DROP TABLE IF EXISTS dns_resolution_consistency_findings;
DROP TABLE IF EXISTS caa_configuration_findings;
DROP TABLE IF EXISTS ns_configuration_findings;
DROP TABLE IF EXISTS cname_redirection_findings;
DROP TABLE IF EXISTS open_port_findings;
DROP TABLE IF EXISTS dmarc_findings;
DROP TABLE IF EXISTS dkim_findings;
DROP TABLE IF EXISTS spf_findings;
DROP TABLE IF EXISTS dnssec_findings;
DROP TABLE IF EXISTS zone_transfer_findings;
DROP TABLE IF EXISTS dangling_cname_findings;

-- Drop ENUM types
DROP TYPE IF EXISTS finding_status;
DROP TYPE IF EXISTS finding_severity;
DROP TYPE IF EXISTS transfer_type;
-- +goose StatementEnd
