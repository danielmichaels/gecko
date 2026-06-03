-- +goose Up
-- +goose StatementBegin
-- The observation log (00007) is now authoritative for the 13 DNS record types,
-- so their trigger-driven *_history shadow tables are redundant and can be
-- decommissioned. This collapses 13 near-identical record_*_history() functions
-- and 26 triggers into the single domain_observations log.
--
-- Deliberately KEPT (not yet covered by the observation log): certificates_history
-- (00003), the assessor findings *_history tables (00005), and
-- zone_transfer_attempts_history + the delete_zone_transfer_history workaround
-- (00006). updated_at_trigger() and the trigger_updated_at_* triggers are
-- unrelated to history and are kept. No backfill of old *_history rows is done —
-- the project is pre-alpha with no production history worth migrating.
DROP TRIGGER IF EXISTS a_records_history_insert_update_trigger ON a_records;
DROP TRIGGER IF EXISTS a_records_history_delete_trigger ON a_records;
DROP TRIGGER IF EXISTS aaaa_records_history_insert_update_trigger ON aaaa_records;
DROP TRIGGER IF EXISTS aaaa_records_history_delete_trigger ON aaaa_records;
DROP TRIGGER IF EXISTS cname_records_history_insert_update_trigger ON cname_records;
DROP TRIGGER IF EXISTS cname_records_history_delete_trigger ON cname_records;
DROP TRIGGER IF EXISTS mx_records_history_insert_update_trigger ON mx_records;
DROP TRIGGER IF EXISTS mx_records_history_delete_trigger ON mx_records;
DROP TRIGGER IF EXISTS txt_records_history_insert_update_trigger ON txt_records;
DROP TRIGGER IF EXISTS txt_records_history_delete_trigger ON txt_records;
DROP TRIGGER IF EXISTS ns_records_history_insert_update_trigger ON ns_records;
DROP TRIGGER IF EXISTS ns_records_history_delete_trigger ON ns_records;
DROP TRIGGER IF EXISTS ptr_records_history_insert_update_trigger ON ptr_records;
DROP TRIGGER IF EXISTS ptr_records_history_delete_trigger ON ptr_records;
DROP TRIGGER IF EXISTS srv_records_history_insert_update_trigger ON srv_records;
DROP TRIGGER IF EXISTS srv_records_history_delete_trigger ON srv_records;
DROP TRIGGER IF EXISTS soa_records_history_insert_update_trigger ON soa_records;
DROP TRIGGER IF EXISTS soa_records_history_delete_trigger ON soa_records;
DROP TRIGGER IF EXISTS dnskey_records_history_insert_update_trigger ON dnskey_records;
DROP TRIGGER IF EXISTS dnskey_records_history_delete_trigger ON dnskey_records;
DROP TRIGGER IF EXISTS ds_records_history_insert_update_trigger ON ds_records;
DROP TRIGGER IF EXISTS ds_records_history_delete_trigger ON ds_records;
DROP TRIGGER IF EXISTS rrsig_records_history_insert_update_trigger ON rrsig_records;
DROP TRIGGER IF EXISTS rrsig_records_history_delete_trigger ON rrsig_records;
DROP TRIGGER IF EXISTS caa_records_history_insert_update_trigger ON caa_records;
DROP TRIGGER IF EXISTS caa_records_history_delete_trigger ON caa_records;

DROP FUNCTION IF EXISTS record_a_history();
DROP FUNCTION IF EXISTS record_aaaa_history();
DROP FUNCTION IF EXISTS record_cname_history();
DROP FUNCTION IF EXISTS record_mx_history();
DROP FUNCTION IF EXISTS record_txt_history();
DROP FUNCTION IF EXISTS record_ns_history();
DROP FUNCTION IF EXISTS record_ptr_history();
DROP FUNCTION IF EXISTS record_srv_history();
DROP FUNCTION IF EXISTS record_soa_history();
DROP FUNCTION IF EXISTS record_dnskey_history();
DROP FUNCTION IF EXISTS record_ds_history();
DROP FUNCTION IF EXISTS record_rrsig_history();
DROP FUNCTION IF EXISTS record_caa_history();

DROP TABLE IF EXISTS a_records_history;
DROP TABLE IF EXISTS aaaa_records_history;
DROP TABLE IF EXISTS cname_records_history;
DROP TABLE IF EXISTS mx_records_history;
DROP TABLE IF EXISTS txt_records_history;
DROP TABLE IF EXISTS ns_records_history;
DROP TABLE IF EXISTS ptr_records_history;
DROP TABLE IF EXISTS srv_records_history;
DROP TABLE IF EXISTS soa_records_history;
DROP TABLE IF EXISTS dnskey_records_history;
DROP TABLE IF EXISTS ds_records_history;
DROP TABLE IF EXISTS rrsig_records_history;
DROP TABLE IF EXISTS caa_records_history;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Recreate the DNS record history tables, functions, and triggers exactly as
-- defined in 00002 (the live *_records tables themselves are untouched here).
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
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO ptr_records_history (record_id, target, change_type)
        VALUES (NEW.id, NEW.target, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.target IS DISTINCT FROM NEW.target) THEN
            INSERT INTO ptr_records_history (record_id, target, change_type)
            VALUES (NEW.id, NEW.target, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
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
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO srv_records_history (record_id, target, port, weight, priority, change_type)
        VALUES (NEW.id, NEW.target, NEW.port, NEW.weight, NEW.priority, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.target IS DISTINCT FROM NEW.target OR
            OLD.port IS DISTINCT FROM NEW.port OR
            OLD.weight IS DISTINCT FROM NEW.weight OR
            OLD.priority IS DISTINCT FROM NEW.priority) THEN
            INSERT INTO srv_records_history (record_id, target, port, weight, priority, change_type)
            VALUES (NEW.id, NEW.target, NEW.port, NEW.weight, NEW.priority, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
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
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO soa_records_history (record_id, nameserver, email, serial, refresh, retry, expire, minimum_ttl,
                                         change_type)
        VALUES (NEW.id, NEW.nameserver, NEW.email, NEW.serial, NEW.refresh, NEW.retry, NEW.expire, NEW.minimum_ttl,
                'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
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
    ELSIF (TG_OP = 'DELETE') THEN
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

CREATE TRIGGER a_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON a_records FOR EACH ROW EXECUTE FUNCTION record_a_history();
CREATE TRIGGER a_records_history_delete_trigger BEFORE DELETE ON a_records FOR EACH ROW EXECUTE FUNCTION record_a_history();
CREATE TRIGGER aaaa_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON aaaa_records FOR EACH ROW EXECUTE FUNCTION record_aaaa_history();
CREATE TRIGGER aaaa_records_history_delete_trigger BEFORE DELETE ON aaaa_records FOR EACH ROW EXECUTE FUNCTION record_aaaa_history();
CREATE TRIGGER cname_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON cname_records FOR EACH ROW EXECUTE FUNCTION record_cname_history();
CREATE TRIGGER cname_records_history_delete_trigger BEFORE DELETE ON cname_records FOR EACH ROW EXECUTE FUNCTION record_cname_history();
CREATE TRIGGER mx_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON mx_records FOR EACH ROW EXECUTE FUNCTION record_mx_history();
CREATE TRIGGER mx_records_history_delete_trigger BEFORE DELETE ON mx_records FOR EACH ROW EXECUTE FUNCTION record_mx_history();
CREATE TRIGGER txt_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON txt_records FOR EACH ROW EXECUTE FUNCTION record_txt_history();
CREATE TRIGGER txt_records_history_delete_trigger BEFORE DELETE ON txt_records FOR EACH ROW EXECUTE FUNCTION record_txt_history();
CREATE TRIGGER ns_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON ns_records FOR EACH ROW EXECUTE FUNCTION record_ns_history();
CREATE TRIGGER ns_records_history_delete_trigger BEFORE DELETE ON ns_records FOR EACH ROW EXECUTE FUNCTION record_ns_history();
CREATE TRIGGER ptr_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON ptr_records FOR EACH ROW EXECUTE FUNCTION record_ptr_history();
CREATE TRIGGER ptr_records_history_delete_trigger BEFORE DELETE ON ptr_records FOR EACH ROW EXECUTE FUNCTION record_ptr_history();
CREATE TRIGGER srv_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON srv_records FOR EACH ROW EXECUTE FUNCTION record_srv_history();
CREATE TRIGGER srv_records_history_delete_trigger BEFORE DELETE ON srv_records FOR EACH ROW EXECUTE FUNCTION record_srv_history();
CREATE TRIGGER soa_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON soa_records FOR EACH ROW EXECUTE FUNCTION record_soa_history();
CREATE TRIGGER soa_records_history_delete_trigger BEFORE DELETE ON soa_records FOR EACH ROW EXECUTE FUNCTION record_soa_history();
CREATE TRIGGER dnskey_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON dnskey_records FOR EACH ROW EXECUTE FUNCTION record_dnskey_history();
CREATE TRIGGER dnskey_records_history_delete_trigger BEFORE DELETE ON dnskey_records FOR EACH ROW EXECUTE FUNCTION record_dnskey_history();
CREATE TRIGGER ds_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON ds_records FOR EACH ROW EXECUTE FUNCTION record_ds_history();
CREATE TRIGGER ds_records_history_delete_trigger BEFORE DELETE ON ds_records FOR EACH ROW EXECUTE FUNCTION record_ds_history();
CREATE TRIGGER rrsig_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON rrsig_records FOR EACH ROW EXECUTE FUNCTION record_rrsig_history();
CREATE TRIGGER rrsig_records_history_delete_trigger BEFORE DELETE ON rrsig_records FOR EACH ROW EXECUTE FUNCTION record_rrsig_history();
CREATE TRIGGER caa_records_history_insert_update_trigger AFTER INSERT OR UPDATE ON caa_records FOR EACH ROW EXECUTE FUNCTION record_caa_history();
CREATE TRIGGER caa_records_history_delete_trigger BEFORE DELETE ON caa_records FOR EACH ROW EXECUTE FUNCTION record_caa_history();
-- +goose StatementEnd
