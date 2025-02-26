-- +goose Up
-- +goose StatementBegin
CREATE TYPE domain_type AS ENUM ('tld', 'subdomain', 'wildcard', 'old', 'other');
CREATE TYPE domain_source AS ENUM ('user_supplied', 'discovered');
CREATE TYPE domain_status AS ENUM ('active', 'inactive', 'pending');
CREATE TABLE IF NOT EXISTS domains
(
    id          SERIAL PRIMARY KEY,
    uid         TEXT UNIQUE                 NOT NULL DEFAULT ('domain_' || generate_uid(8)),
    tenant_id   INTEGER REFERENCES tenants (id) ON DELETE CASCADE,
    name        VARCHAR(255)                NOT NULL,
    domain_type domain_type                 NOT NULL DEFAULT 'subdomain',
    source      domain_source               NOT NULL DEFAULT 'discovered',
    status      domain_status               NOT NULL DEFAULT 'active',
    created_at  TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE TABLE a_records
(
    id           SERIAL PRIMARY KEY,
    uid          TEXT UNIQUE                 NOT NULL DEFAULT ('a_' || generate_uid(8)),
    domain_id    INT REFERENCES domains (id) ON DELETE CASCADE,
    ipv4_address TEXT                        NOT NULL,
    created_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, ipv4_address)
);

CREATE TABLE aaaa_records
(
    id           SERIAL PRIMARY KEY,
    uid          TEXT UNIQUE                 NOT NULL DEFAULT ('aaaa_' || generate_uid(8)),
    domain_id    INT REFERENCES domains (id) ON DELETE CASCADE,
    ipv6_address TEXT                        NOT NULL,
    created_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, ipv6_address)
);
CREATE TABLE IF NOT EXISTS cname_records
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('cname_' || generate_uid(8)),
    domain_id  INT REFERENCES domains (id) ON DELETE CASCADE,
    target     TEXT                        NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, target)
);

CREATE TABLE IF NOT EXISTS mx_records
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('mx_' || generate_uid(8)),
    domain_id  INT REFERENCES domains (id) ON DELETE CASCADE,
    preference INT                         NOT NULL,
    target     TEXT                        NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, preference, target)
);

CREATE TABLE IF NOT EXISTS txt_records
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('txt_' || generate_uid(8)),
    domain_id  INT REFERENCES domains (id) ON DELETE CASCADE,
    value      TEXT                        NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, value)
);
CREATE TABLE IF NOT EXISTS ns_records
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('ns_' || generate_uid(8)),
    domain_id  INT REFERENCES domains (id) ON DELETE CASCADE,
    nameserver TEXT                        NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, nameserver)
);
CREATE TABLE IF NOT EXISTS ptr_records
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('ptr_' || generate_uid(8)),
    domain_id  INT REFERENCES domains (id) ON DELETE CASCADE,
    target     TEXT                        NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, target)
);

CREATE TABLE IF NOT EXISTS srv_records
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('srv_' || generate_uid(8)),
    domain_id  INT REFERENCES domains (id) ON DELETE CASCADE,
    target     TEXT                        NOT NULL,
    port       INTEGER                     NOT NULL,
    weight     INTEGER                     NOT NULL,
    priority   INTEGER                     NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, target, port, priority)
);

CREATE TABLE IF NOT EXISTS soa_records
(
    id          SERIAL PRIMARY KEY,
    uid         TEXT UNIQUE                 NOT NULL DEFAULT ('soa_' || generate_uid(8)),
    domain_id   INT REFERENCES domains (id) ON DELETE CASCADE,
    nameserver  TEXT                        NOT NULL,
    email       TEXT                        NOT NULL,
    serial      BIGINT                      NOT NULL,
    refresh     INTEGER                     NOT NULL,
    retry       INTEGER                     NOT NULL,
    expire      INTEGER                     NOT NULL,
    minimum_ttl INTEGER                     NOT NULL,
    created_at  TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id)
);
CREATE TABLE IF NOT EXISTS dnskey_records
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('dnskey_' || generate_uid(8)),
    domain_id  INT REFERENCES domains (id) ON DELETE CASCADE,
    public_key TEXT                        NOT NULL,
    flags      INTEGER                     NOT NULL,
    protocol   INTEGER                     NOT NULL,
    algorithm  INTEGER                     NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, public_key)
);

CREATE TABLE IF NOT EXISTS ds_records
(
    id          SERIAL PRIMARY KEY,
    uid         TEXT UNIQUE                 NOT NULL DEFAULT ('ds_' || generate_uid(8)),
    domain_id   INT REFERENCES domains (id) ON DELETE CASCADE,
    key_tag     INTEGER                     NOT NULL,
    algorithm   INTEGER                     NOT NULL,
    digest_type INTEGER                     NOT NULL,
    digest      TEXT                        NOT NULL,
    created_at  TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, digest)
);

CREATE TABLE IF NOT EXISTS rrsig_records
(
    id           SERIAL PRIMARY KEY,
    uid          TEXT UNIQUE                 NOT NULL DEFAULT ('rrsig_' || generate_uid(8)),
    domain_id    INT REFERENCES domains (id) ON DELETE CASCADE,
    type_covered INTEGER                     NOT NULL,
    algorithm    INTEGER                     NOT NULL,
    labels       INTEGER                     NOT NULL,
    original_ttl INTEGER                     NOT NULL,
    expiration   INTEGER                     NOT NULL,
    inception    INTEGER                     NOT NULL,
    key_tag      INTEGER                     NOT NULL,
    signer_name  TEXT                        NOT NULL,
    signature    TEXT                        NOT NULL,
    created_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, type_covered, signer_name)
);
CREATE TABLE IF NOT EXISTS caa_records
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('caa_' || generate_uid(8)),
    domain_id  INT REFERENCES domains (id) ON DELETE CASCADE,
    flags      INTEGER                     NOT NULL,
    tag        TEXT                        NOT NULL,
    value      TEXT                        NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, tag, value)
);
-- History tables
CREATE TABLE a_records_history
(
    id           SERIAL PRIMARY KEY,
    record_id    INT REFERENCES a_records (id) ON DELETE CASCADE,
    ipv4_address TEXT NOT NULL,
    change_type  TEXT NOT NULL,
    changed_at   TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE aaaa_records_history
(
    id           SERIAL PRIMARY KEY,
    record_id    INT REFERENCES aaaa_records (id) ON DELETE CASCADE,
    ipv6_address TEXT NOT NULL,
    change_type  TEXT NOT NULL,
    changed_at   TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE cname_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES cname_records (id) ON DELETE CASCADE,
    target      TEXT NOT NULL,
    change_type TEXT NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE mx_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES mx_records (id) ON DELETE CASCADE,
    preference  INT  NOT NULL,
    target      TEXT NOT NULL,
    change_type TEXT NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE txt_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES txt_records (id) ON DELETE CASCADE,
    value       TEXT NOT NULL,
    change_type TEXT NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE ns_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES ns_records (id) ON DELETE CASCADE,
    nameserver  TEXT NOT NULL,
    change_type TEXT NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE ptr_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES ptr_records (id) ON DELETE CASCADE,
    target      TEXT NOT NULL,
    change_type TEXT NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE srv_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES srv_records (id) ON DELETE CASCADE,
    target      TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    weight      INTEGER NOT NULL,
    priority    INTEGER NOT NULL,
    change_type TEXT    NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE soa_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES soa_records (id) ON DELETE CASCADE,
    nameserver  TEXT    NOT NULL,
    email       TEXT    NOT NULL,
    serial      BIGINT  NOT NULL,
    refresh     INTEGER NOT NULL,
    retry       INTEGER NOT NULL,
    expire      INTEGER NOT NULL,
    minimum_ttl INTEGER NOT NULL,
    change_type TEXT    NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE dnskey_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES dnskey_records (id) ON DELETE CASCADE,
    public_key  TEXT    NOT NULL,
    flags       INTEGER NOT NULL,
    protocol    INTEGER NOT NULL,
    algorithm   INTEGER NOT NULL,
    change_type TEXT    NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE ds_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES ds_records (id) ON DELETE CASCADE,
    key_tag     INTEGER NOT NULL,
    algorithm   INTEGER NOT NULL,
    digest_type INTEGER NOT NULL,
    digest      TEXT    NOT NULL,
    change_type TEXT    NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE rrsig_records_history
(
    id           SERIAL PRIMARY KEY,
    record_id    INT REFERENCES rrsig_records (id) ON DELETE CASCADE,
    type_covered INTEGER NOT NULL,
    algorithm    INTEGER NOT NULL,
    labels       INTEGER NOT NULL,
    original_ttl INTEGER NOT NULL,
    expiration   INTEGER NOT NULL,
    inception    INTEGER NOT NULL,
    key_tag      INTEGER NOT NULL,
    signer_name  TEXT    NOT NULL,
    signature    TEXT    NOT NULL,
    change_type  TEXT    NOT NULL,
    changed_at   TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE caa_records_history
(
    id          SERIAL PRIMARY KEY,
    record_id   INT REFERENCES caa_records (id) ON DELETE CASCADE,
    flags       INTEGER NOT NULL,
    tag         TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    change_type TEXT    NOT NULL,
    changed_at  TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);
CREATE TRIGGER trigger_updated_at_a
    BEFORE UPDATE
    ON a_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_aaaa
    BEFORE UPDATE
    ON aaaa_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_txt
    BEFORE UPDATE
    ON txt_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_ns
    BEFORE UPDATE
    ON ns_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_cname
    BEFORE UPDATE
    ON cname_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_mx
    BEFORE UPDATE
    ON mx_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_mx
    BEFORE UPDATE
    ON soa_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_mx
    BEFORE UPDATE
    ON ptr_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_mx
    BEFORE UPDATE
    ON srv_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_dnskey
    BEFORE UPDATE
    ON dnskey_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_ds
    BEFORE UPDATE
    ON ds_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_rrsig
    BEFORE UPDATE
    ON rrsig_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
CREATE TRIGGER trigger_updated_at_caa
    BEFORE UPDATE
    ON caa_records
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();
-- AAAA Record Trigger
CREATE OR REPLACE FUNCTION record_aaaa_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO aaaa_records_history (record_id, ipv6_address, change_type)
        VALUES (NEW.id, NEW.ipv6_address, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.ipv6_address IS DISTINCT FROM NEW.ipv6_address) THEN
            INSERT INTO aaaa_records_history (record_id, ipv6_address, change_type)
            VALUES (NEW.id, NEW.ipv6_address, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO aaaa_records_history (record_id, ipv6_address, change_type)
        VALUES (OLD.id, OLD.ipv6_address, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- A Record Trigger
CREATE OR REPLACE FUNCTION record_a_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO a_records_history (record_id, ipv4_address, change_type)
        VALUES (NEW.id, NEW.ipv4_address, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.ipv4_address IS DISTINCT FROM NEW.ipv4_address) THEN
            INSERT INTO a_records_history (record_id, ipv4_address, change_type)
            VALUES (NEW.id, NEW.ipv4_address, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO a_records_history (record_id, ipv4_address, change_type)
        VALUES (OLD.id, OLD.ipv4_address, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- MX Record Trigger
CREATE OR REPLACE FUNCTION record_mx_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO mx_records_history (record_id, preference, target, change_type)
        VALUES (NEW.id, NEW.preference, NEW.target, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.preference IS DISTINCT FROM NEW.preference OR OLD.target IS DISTINCT FROM NEW.target) THEN
            INSERT INTO mx_records_history (record_id, preference, target, change_type)
            VALUES (NEW.id, NEW.preference, NEW.target, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO mx_records_history (record_id, preference, target, change_type)
        VALUES (OLD.id, OLD.preference, OLD.target, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- TXT Record Trigger
CREATE OR REPLACE FUNCTION record_txt_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO txt_records_history (record_id, value, change_type)
        VALUES (NEW.id, NEW.value, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.value IS DISTINCT FROM NEW.value) THEN
            INSERT INTO txt_records_history (record_id, value, change_type)
            VALUES (NEW.id, NEW.value, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO txt_records_history (record_id, value, change_type)
        VALUES (OLD.id, OLD.value, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- CNAME Record Trigger
CREATE OR REPLACE FUNCTION record_cname_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO cname_records_history (record_id, target, change_type)
        VALUES (NEW.id, NEW.target, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.target IS DISTINCT FROM NEW.target) THEN
            INSERT INTO cname_records_history (record_id, target, change_type)
            VALUES (NEW.id, NEW.target, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO cname_records_history (record_id, target, change_type)
        VALUES (OLD.id, OLD.target, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- NS Record Trigger
CREATE OR REPLACE FUNCTION record_ns_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO ns_records_history (record_id, nameserver, change_type)
        VALUES (NEW.id, NEW.nameserver, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.nameserver IS DISTINCT FROM NEW.nameserver) THEN
            INSERT INTO ns_records_history (record_id, nameserver, change_type)
            VALUES (NEW.id, NEW.nameserver, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO ns_records_history (record_id, nameserver, change_type)
        VALUES (OLD.id, OLD.nameserver, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION record_ptr_history() RETURNS TRIGGER AS
$$
BEGIN
    IF
        (TG_OP = 'INSERT')
    THEN
        INSERT INTO ptr_records_history (record_id, target, change_type)
        VALUES (NEW.id, NEW.target, 'created');
        RETURN NEW;
    ELSIF
        (TG_OP = 'UPDATE')
    THEN
        IF (OLD.target IS DISTINCT FROM NEW.target) THEN
            INSERT INTO ptr_records_history (record_id, target, change_type)
            VALUES (NEW.id, NEW.target, 'updated');
        END IF;
        RETURN NEW;
    ELSIF
        (TG_OP = 'DELETE')
    THEN
        INSERT INTO ptr_records_history (record_id, target, change_type)
        VALUES (OLD.id, OLD.target, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION record_srv_history() RETURNS TRIGGER AS
$$
BEGIN
    IF
        (TG_OP = 'INSERT')
    THEN
        INSERT INTO srv_records_history (record_id, target, port, weight, priority, change_type)
        VALUES (NEW.id, NEW.target, NEW.port, NEW.weight, NEW.priority, 'created');
        RETURN NEW;
    ELSIF
        (TG_OP = 'UPDATE')
    THEN
        IF (OLD.target IS DISTINCT FROM NEW.target OR
            OLD.port IS DISTINCT FROM NEW.port OR
            OLD.weight IS DISTINCT FROM NEW.weight OR
            OLD.priority IS DISTINCT FROM NEW.priority) THEN
            INSERT INTO srv_records_history (record_id, target, port, weight, priority, change_type)
            VALUES (NEW.id, NEW.target, NEW.port, NEW.weight, NEW.priority, 'updated');
        END IF;
        RETURN NEW;
    ELSIF
        (TG_OP = 'DELETE')
    THEN
        INSERT INTO srv_records_history (record_id, target, port, weight, priority, change_type)
        VALUES (OLD.id, OLD.target, OLD.port, OLD.weight, OLD.priority, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION record_soa_history() RETURNS TRIGGER AS
$$
BEGIN
    IF
        (TG_OP = 'INSERT')
    THEN
        INSERT INTO soa_records_history (record_id, nameserver, email, serial, refresh, retry, expire, minimum_ttl,
                                         change_type)
        VALUES (NEW.id, NEW.nameserver, NEW.email, NEW.serial, NEW.refresh, NEW.retry, NEW.expire, NEW.minimum_ttl,
                'created');
        RETURN NEW;
    ELSIF
        (TG_OP = 'UPDATE')
    THEN
        IF (OLD.nameserver IS DISTINCT FROM NEW.nameserver OR
            OLD.email IS DISTINCT FROM NEW.email OR
            OLD.serial IS DISTINCT FROM NEW.serial OR
            OLD.refresh IS DISTINCT FROM NEW.refresh OR
            OLD.retry IS DISTINCT FROM NEW.retry OR
            OLD.expire IS DISTINCT FROM NEW.expire OR
            OLD.minimum_ttl IS DISTINCT FROM NEW.minimum_ttl) THEN
            INSERT INTO soa_records_history (record_id, nameserver, email, serial, refresh, retry, expire, minimum_ttl,
                                             change_type)
            VALUES (NEW.id, NEW.nameserver, NEW.email, NEW.serial, NEW.refresh, NEW.retry, NEW.expire, NEW.minimum_ttl,
                    'updated');
        END IF;
        RETURN NEW;
    ELSIF
        (TG_OP = 'DELETE')
    THEN
        INSERT INTO soa_records_history (record_id, nameserver, email, serial, refresh, retry, expire, minimum_ttl,
                                         change_type)
        VALUES (OLD.id, OLD.nameserver, OLD.email, OLD.serial, OLD.refresh, OLD.retry, OLD.expire, OLD.minimum_ttl,
                'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION record_dnskey_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO dnskey_records_history (record_id, public_key, flags, protocol, algorithm, change_type)
        VALUES (NEW.id, NEW.public_key, NEW.flags, NEW.protocol, NEW.algorithm, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.public_key IS DISTINCT FROM NEW.public_key OR
            OLD.flags IS DISTINCT FROM NEW.flags OR
            OLD.protocol IS DISTINCT FROM NEW.protocol OR
            OLD.algorithm IS DISTINCT FROM NEW.algorithm) THEN
            INSERT INTO dnskey_records_history (record_id, public_key, flags, protocol, algorithm, change_type)
            VALUES (NEW.id, NEW.public_key, NEW.flags, NEW.protocol, NEW.algorithm, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO dnskey_records_history (record_id, public_key, flags, protocol, algorithm, change_type)
        VALUES (OLD.id, OLD.public_key, OLD.flags, OLD.protocol, OLD.algorithm, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION record_ds_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO ds_records_history (record_id, key_tag, algorithm, digest_type, digest, change_type)
        VALUES (NEW.id, NEW.key_tag, NEW.algorithm, NEW.digest_type, NEW.digest, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.key_tag IS DISTINCT FROM NEW.key_tag OR
            OLD.algorithm IS DISTINCT FROM NEW.algorithm OR
            OLD.digest_type IS DISTINCT FROM NEW.digest_type OR
            OLD.digest IS DISTINCT FROM NEW.digest) THEN
            INSERT INTO ds_records_history (record_id, key_tag, algorithm, digest_type, digest, change_type)
            VALUES (NEW.id, NEW.key_tag, NEW.algorithm, NEW.digest_type, NEW.digest, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO ds_records_history (record_id, key_tag, algorithm, digest_type, digest, change_type)
        VALUES (OLD.id, OLD.key_tag, OLD.algorithm, OLD.digest_type, OLD.digest, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION record_rrsig_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO rrsig_records_history (record_id, type_covered, algorithm, labels, original_ttl, expiration,
                                           inception, key_tag, signer_name, signature, change_type)
        VALUES (NEW.id, NEW.type_covered, NEW.algorithm, NEW.labels, NEW.original_ttl, NEW.expiration, NEW.inception,
                NEW.key_tag, NEW.signer_name, NEW.signature, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.type_covered IS DISTINCT FROM NEW.type_covered OR
            OLD.algorithm IS DISTINCT FROM NEW.algorithm OR
            OLD.labels IS DISTINCT FROM NEW.labels OR
            OLD.original_ttl IS DISTINCT FROM NEW.original_ttl OR
            OLD.expiration IS DISTINCT FROM NEW.expiration OR
            OLD.inception IS DISTINCT FROM NEW.inception OR
            OLD.key_tag IS DISTINCT FROM NEW.key_tag OR
            OLD.signer_name IS DISTINCT FROM NEW.signer_name OR
            OLD.signature IS DISTINCT FROM NEW.signature) THEN
            INSERT INTO rrsig_records_history (record_id, type_covered, algorithm, labels, original_ttl, expiration,
                                               inception, key_tag, signer_name, signature, change_type)
            VALUES (NEW.id, NEW.type_covered, NEW.algorithm, NEW.labels, NEW.original_ttl, NEW.expiration,
                    NEW.inception, NEW.key_tag, NEW.signer_name, NEW.signature, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO rrsig_records_history (record_id, type_covered, algorithm, labels, original_ttl, expiration,
                                           inception, key_tag, signer_name, signature, change_type)
        VALUES (OLD.id, OLD.type_covered, OLD.algorithm, OLD.labels, OLD.original_ttl, OLD.expiration, OLD.inception,
                OLD.key_tag, OLD.signer_name, OLD.signature, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION record_caa_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO caa_records_history (record_id, flags, tag, value, change_type)
        VALUES (NEW.id, NEW.flags, NEW.tag, NEW.value, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.flags IS DISTINCT FROM NEW.flags OR
            OLD.tag IS DISTINCT FROM NEW.tag OR
            OLD.value IS DISTINCT FROM NEW.value) THEN
            INSERT INTO caa_records_history (record_id, flags, tag, value, change_type)
            VALUES (NEW.id, NEW.flags, NEW.tag, NEW.value, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO caa_records_history (record_id, flags, tag, value, change_type)
        VALUES (OLD.id, OLD.flags, OLD.tag, OLD.value, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- update triggers
CREATE TRIGGER a_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON a_records
    FOR EACH ROW
EXECUTE FUNCTION record_a_history();
CREATE TRIGGER aaaa_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON aaaa_records
    FOR EACH ROW
EXECUTE FUNCTION record_aaaa_history();
CREATE TRIGGER mx_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON mx_records
    FOR EACH ROW
EXECUTE FUNCTION record_mx_history();
CREATE TRIGGER cname_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON cname_records
    FOR EACH ROW
EXECUTE FUNCTION record_cname_history();
CREATE TRIGGER txt_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON txt_records
    FOR EACH ROW
EXECUTE FUNCTION record_txt_history();
CREATE TRIGGER ns_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON ns_records
    FOR EACH ROW
EXECUTE FUNCTION record_ns_history();
CREATE TRIGGER ptr_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON ptr_records
    FOR EACH ROW
EXECUTE FUNCTION record_ptr_history();
CREATE TRIGGER srv_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON srv_records
    FOR EACH ROW
EXECUTE FUNCTION record_srv_history();
CREATE TRIGGER soa_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON soa_records
    FOR EACH ROW
EXECUTE FUNCTION record_soa_history();
CREATE TRIGGER dnskey_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON dnskey_records
    FOR EACH ROW
EXECUTE FUNCTION record_dnskey_history();

CREATE TRIGGER ds_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON ds_records
    FOR EACH ROW
EXECUTE FUNCTION record_ds_history();

CREATE TRIGGER rrsig_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON rrsig_records
    FOR EACH ROW
EXECUTE FUNCTION record_rrsig_history();

CREATE TRIGGER caa_records_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON caa_records
    FOR EACH ROW
EXECUTE FUNCTION record_caa_history();

CREATE INDEX idx_domains_tenants ON domains (tenant_id);
CREATE INDEX idx_domains_type ON domains (domain_type);
CREATE INDEX idx_domains_source ON domains (source);
CREATE INDEX idx_domains_status ON domains (status);

CREATE INDEX idx_a_domain_id ON a_records (domain_id);
CREATE INDEX idx_aaaa_domain_id ON aaaa_records (domain_id);
CREATE INDEX idx_cname_domain_id ON cname_records (domain_id);
CREATE INDEX idx_mx_domain_id ON mx_records (domain_id);
CREATE INDEX idx_txt_domain_id ON txt_records (domain_id);
CREATE INDEX idx_ns_domain_id ON ns_records (domain_id);
CREATE INDEX idx_ptr_domain_id ON ptr_records (domain_id);
CREATE INDEX idx_srv_domain_id ON srv_records (domain_id);
CREATE INDEX idx_soa_domain_id ON soa_records (domain_id);
CREATE INDEX idx_ptr_target ON ptr_records (target);
CREATE INDEX idx_srv_target ON srv_records (target);
CREATE INDEX idx_srv_priority_port ON srv_records (priority, port);
CREATE INDEX idx_dnskey_domain_id ON dnskey_records (domain_id);
CREATE INDEX idx_ds_domain_id ON ds_records (domain_id);
CREATE INDEX idx_rrsig_domain_id ON rrsig_records (domain_id);
CREATE INDEX idx_dnskey_algorithm ON dnskey_records (algorithm);
CREATE INDEX idx_ds_key_tag ON ds_records (key_tag);
CREATE INDEX idx_rrsig_type_covered ON rrsig_records (type_covered);
CREATE INDEX idx_rrsig_expiration ON rrsig_records (expiration);
CREATE INDEX idx_rrsig_signer_name ON rrsig_records (signer_name);
CREATE INDEX idx_caa_domain_id ON caa_records (domain_id);
CREATE INDEX idx_caa_tag ON caa_records (tag);
CREATE INDEX idx_caa_tag_value ON caa_records (tag, value);
-- Index for searching by target/value
CREATE INDEX idx_cname_target ON cname_records (target);
CREATE INDEX idx_mx_target ON mx_records (target);
CREATE INDEX idx_ns_nameserver ON ns_records (nameserver);
-- Composite index for MX records to optimize preference+target queries
CREATE INDEX idx_mx_preference_target ON mx_records (preference, target);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS rrsig_records_history_trigger ON rrsig_records;
DROP TRIGGER IF EXISTS ds_records_history_trigger ON ds_records;
DROP TRIGGER IF EXISTS dnskey_records_history_trigger ON dnskey_records;
DROP TRIGGER IF EXISTS soa_records_history_trigger ON soa_records;
DROP TRIGGER IF EXISTS srv_records_history_trigger ON srv_records;
DROP TRIGGER IF EXISTS ptr_records_history_trigger ON ptr_records;
DROP TRIGGER IF EXISTS ns_records_history_trigger ON ns_records;
DROP TRIGGER IF EXISTS txt_records_history_trigger ON txt_records;
DROP TRIGGER IF EXISTS mx_records_history_trigger ON mx_records;
DROP TRIGGER IF EXISTS cname_records_history_trigger ON cname_records;
DROP TRIGGER IF EXISTS aaaa_records_history_trigger ON aaaa_records;
DROP TRIGGER IF EXISTS a_records_history_trigger ON a_records;
DROP TRIGGER IF EXISTS caa_records_history_trigger ON caa_records;

DROP TRIGGER IF EXISTS trigger_updated_at_rrsig ON rrsig_records;
DROP TRIGGER IF EXISTS trigger_updated_at_ds ON ds_records;
DROP TRIGGER IF EXISTS trigger_updated_at_dnskey ON dnskey_records;
DROP TRIGGER IF EXISTS trigger_updated_at_soa ON soa_records;
DROP TRIGGER IF EXISTS trigger_updated_at_srv ON srv_records;
DROP TRIGGER IF EXISTS trigger_updated_at_ptr ON ptr_records;
DROP TRIGGER IF EXISTS trigger_updated_at_ns ON ns_records;
DROP TRIGGER IF EXISTS trigger_updated_at_txt ON txt_records;
DROP TRIGGER IF EXISTS trigger_updated_at_mx ON mx_records;
DROP TRIGGER IF EXISTS trigger_updated_at_cname ON cname_records;
DROP TRIGGER IF EXISTS trigger_updated_at_aaaa ON aaaa_records;
DROP TRIGGER IF EXISTS trigger_updated_at_a ON a_records;
DROP TRIGGER IF EXISTS trigger_updated_at_caa ON caa_records;

-- Then drop all functions
DROP FUNCTION IF EXISTS record_rrsig_history();
DROP FUNCTION IF EXISTS record_ds_history();
DROP FUNCTION IF EXISTS record_dnskey_history();
DROP FUNCTION IF EXISTS record_soa_history();
DROP FUNCTION IF EXISTS record_srv_history();
DROP FUNCTION IF EXISTS record_ptr_history();
DROP FUNCTION IF EXISTS record_ns_history();
DROP FUNCTION IF EXISTS record_txt_history();
DROP FUNCTION IF EXISTS record_mx_history();
DROP FUNCTION IF EXISTS record_cname_history();
DROP FUNCTION IF EXISTS record_aaaa_history();
DROP FUNCTION IF EXISTS record_a_history();
DROP FUNCTION IF EXISTS record_caa_history();

DROP TABLE IF EXISTS rrsig_records_history;
DROP TABLE IF EXISTS ds_records_history;
DROP TABLE IF EXISTS dnskey_records_history;
DROP TABLE IF EXISTS soa_records_history;
DROP TABLE IF EXISTS srv_records_history;
DROP TABLE IF EXISTS ptr_records_history;
DROP TABLE IF EXISTS ns_records_history;
DROP TABLE IF EXISTS txt_records_history;
DROP TABLE IF EXISTS mx_records_history;
DROP TABLE IF EXISTS cname_records_history;
DROP TABLE IF EXISTS aaaa_records_history;
DROP TABLE IF EXISTS a_records_history;
DROP TABLE IF EXISTS caa_records_history;

DROP TABLE IF EXISTS rrsig_records;
DROP TABLE IF EXISTS ds_records;
DROP TABLE IF EXISTS dnskey_records;
DROP TABLE IF EXISTS soa_records;
DROP TABLE IF EXISTS srv_records;
DROP TABLE IF EXISTS ptr_records;
DROP TABLE IF EXISTS ns_records;
DROP TABLE IF EXISTS txt_records;
DROP TABLE IF EXISTS mx_records;
DROP TABLE IF EXISTS cname_records;
DROP TABLE IF EXISTS aaaa_records;
DROP TABLE IF EXISTS a_records;
DROP TABLE IF EXISTS caa_records;
DROP TABLE IF EXISTS domains;

DROP TYPE IF EXISTS domain_type;
DROP TYPE IF EXISTS domain_source;
DROP TYPE IF EXISTS domain_status;
-- +goose StatementEnd
