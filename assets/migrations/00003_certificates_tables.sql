-- +goose Up
-- +goose StatementBegin
CREATE TABLE certificates
(
    id              SERIAL PRIMARY KEY,
    domain_id       INT REFERENCES domains (id) ON DELETE CASCADE,
    not_before      TIMESTAMP(0) WITH TIME ZONE NOT NULL,
    not_after       TIMESTAMP(0) WITH TIME ZONE NOT NULL,
    issuer          TEXT                        NOT NULL,
    issuer_org_name TEXT,
    issuer_country  TEXT,
    subject         TEXT                        NOT NULL,
    key_algorithm   TEXT                        NOT NULL,
    key_strength    INTEGER                     NOT NULL,
    sans            TEXT[]                      NOT NULL DEFAULT '{}',
    dns_names       TEXT[]                      NOT NULL DEFAULT '{}',
    is_ca           BOOLEAN                     NOT NULL DEFAULT FALSE,
    issuer_cert_url TEXT[]                      DEFAULT '{}',
    cipher_suite    TEXT                        NOT NULL,
    tls_version     TEXT                        NOT NULL,
    created_at      TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id)
);

CREATE TABLE certificates_history
(
    id              SERIAL PRIMARY KEY,
    record_id       INT REFERENCES certificates (id),
    not_before      TIMESTAMP(0) WITH TIME ZONE NOT NULL,
    not_after       TIMESTAMP(0) WITH TIME ZONE NOT NULL,
    issuer          TEXT                        NOT NULL,
    issuer_org_name TEXT,
    issuer_country  TEXT,
    subject         TEXT                        NOT NULL,
    key_algorithm   TEXT                        NOT NULL,
    key_strength    INTEGER                     NOT NULL,
    sans            TEXT[]                      NOT NULL DEFAULT '{}',
    dns_names       TEXT[]                      NOT NULL DEFAULT '{}',
    is_ca           BOOLEAN                     NOT NULL DEFAULT FALSE,
    issuer_cert_url TEXT[]                      NOT NULL DEFAULT '{}',
    cipher_suite    TEXT                        NOT NULL,
    tls_version     TEXT                        NOT NULL,
    change_type     TEXT                        NOT NULL,
    changed_at      TIMESTAMP(0) WITH TIME ZONE          DEFAULT NOW()
);

-- Triggers
CREATE TRIGGER trigger_updated_at_certificates
    BEFORE UPDATE
    ON certificates
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

-- History trigger function
CREATE OR REPLACE FUNCTION record_certificate_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO certificates_history (record_id, not_before, not_after, issuer, issuer_org_name,
                                                 issuer_country, subject,
                                                 key_algorithm, key_strength, sans, dns_names, is_ca, issuer_cert_url,
                                                 cipher_suite, tls_version,
                                                 change_type)
        VALUES (NEW.id, NEW.not_before, NEW.not_after, NEW.issuer, NEW.issuer_org_name, NEW.issuer_country, NEW.subject,
                NEW.key_algorithm, NEW.key_strength, NEW.sans, NEW.dns_names, NEW.is_ca, NEW.issuer_cert_url,
                NEW.cipher_suite, NEW.tls_version, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO certificates_history (record_id, not_before, not_after, issuer, issuer_org_name,
                                                 issuer_country, subject,
                                                 key_algorithm, key_strength, sans, dns_names, is_ca, issuer_cert_url,
                                                 cipher_suite, tls_version,
                                                 change_type)
        VALUES (NEW.id, NEW.not_before, NEW.not_after, NEW.issuer, NEW.issuer_org_name, NEW.issuer_country, NEW.subject,
                NEW.key_algorithm, NEW.key_strength, NEW.sans, NEW.dns_names, NEW.is_ca, NEW.issuer_cert_url,
                NEW.cipher_suite, NEW.tls_version, 'updated');
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO certificates_history (record_id, not_before, not_after, issuer, issuer_org_name,
                                                 issuer_country, subject,
                                                 key_algorithm, key_strength, sans, dns_names, is_ca, issuer_cert_url,
                                                 cipher_suite, tls_version,
                                                 change_type)
        VALUES (OLD.id, OLD.not_before, OLD.not_after, OLD.issuer, OLD.issuer_org_name, OLD.issuer_country, OLD.subject,
                OLD.key_algorithm, OLD.key_strength, OLD.sans, OLD.dns_names, OLD.is_ca, OLD.issuer_cert_url,
                OLD.cipher_suite, OLD.tls_version, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- History trigger
CREATE TRIGGER certificates_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON certificates
    FOR EACH ROW
EXECUTE FUNCTION record_certificate_history();

-- Indexes
CREATE INDEX idx_cert_domain_id ON certificates (domain_id);
CREATE INDEX idx_cert_expiry ON certificates (not_after);
CREATE INDEX idx_cert_algorithm ON certificates (key_algorithm);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS certificates_history_trigger ON certificates;
DROP TRIGGER IF EXISTS trigger_updated_at_certificates ON certificates;
DROP FUNCTION IF EXISTS record_certificate_history();
DROP TABLE IF EXISTS certificates_history;
DROP TABLE IF EXISTS certificates;
-- +goose StatementEnd
