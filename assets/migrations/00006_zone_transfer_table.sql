-- +goose Up
-- +goose StatementBegin
CREATE TABLE zone_transfer_attempts
(
    id             SERIAL PRIMARY KEY,
    uid            TEXT UNIQUE                 NOT NULL DEFAULT ('zone_transfer_' || generate_uid(8)),
    domain_id      INT REFERENCES domains (id) ON DELETE CASCADE,
    nameserver     TEXT                        NOT NULL,
    transfer_type  transfer_type               NOT NULL,
    was_successful BOOLEAN                     NOT NULL DEFAULT FALSE,
    response_data  JSONB, -- stores response data if successful
    error_message  TEXT,  -- stores error message if failed
    created_at     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, nameserver)
);

CREATE TABLE zone_transfer_attempts_history
(
    id             SERIAL PRIMARY KEY,
    record_id      INT REFERENCES zone_transfer_attempts (id) ON DELETE CASCADE,
    nameserver     TEXT    NOT NULL,
    transfer_type  TEXT    NOT NULL,
    was_successful BOOLEAN NOT NULL,
    response_data  JSONB,
    error_message  TEXT,
    change_type    TEXT    NOT NULL, -- 'created', 'updated', 'deleted'
    changed_at     TIMESTAMP(0) WITH TIME ZONE DEFAULT NOW()
);

-- Trigger for updated_at
CREATE TRIGGER trigger_updated_at_zone_transfer_attempts
    BEFORE UPDATE
    ON zone_transfer_attempts
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

-- History trigger function
CREATE OR REPLACE FUNCTION record_zone_transfer_attempts_history() RETURNS TRIGGER AS
$$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO zone_transfer_attempts_history (record_id, nameserver, transfer_type, was_successful,
                                                    response_data, error_message, change_type)
        VALUES (NEW.id, NEW.nameserver, NEW.transfer_type, NEW.was_successful,
                NEW.response_data, NEW.error_message, 'created');
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.transfer_type IS DISTINCT FROM NEW.transfer_type OR
            OLD.was_successful IS DISTINCT FROM NEW.was_successful OR
            OLD.response_data IS DISTINCT FROM NEW.response_data OR
            OLD.error_message IS DISTINCT FROM NEW.error_message) THEN
            INSERT INTO zone_transfer_attempts_history (record_id, nameserver, transfer_type, was_successful,
                                                        response_data, error_message, change_type)
            VALUES (NEW.id, NEW.nameserver, NEW.transfer_type, NEW.was_successful,
                    NEW.response_data, NEW.error_message, 'updated');
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO zone_transfer_attempts_history (record_id, nameserver, transfer_type, was_successful,
                                                    response_data, error_message, change_type)
        VALUES (OLD.id, OLD.nameserver, OLD.transfer_type, OLD.was_successful,
                OLD.response_data, OLD.error_message, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- History trigger
CREATE TRIGGER zone_transfer_attempts_history_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON zone_transfer_attempts
    FOR EACH ROW
EXECUTE FUNCTION record_zone_transfer_attempts_history();

-- Indexes
CREATE INDEX idx_zone_transfer_success ON zone_transfer_attempts (was_successful);
CREATE INDEX idx_zone_transfer_updated_at ON zone_transfer_attempts (updated_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS zone_transfer_attempts_history_trigger ON zone_transfer_attempts;
DROP TRIGGER IF EXISTS trigger_updated_at_zone_transfer_attempts ON zone_transfer_attempts;
DROP FUNCTION IF EXISTS record_zone_transfer_attempts_history();
DROP TABLE IF EXISTS zone_transfer_attempts_history;
DROP TABLE IF EXISTS zone_transfer_attempts;
-- +goose StatementEnd
