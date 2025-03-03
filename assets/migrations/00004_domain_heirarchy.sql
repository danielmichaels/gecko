-- +goose Up
-- +goose StatementBegin
ALTER TABLE domains
    ADD COLUMN parent_domain_id INTEGER REFERENCES domains (id) ON DELETE CASCADE;
CREATE INDEX idx_domains_parent_domain_id ON domains (parent_domain_id);
CREATE OR REPLACE FUNCTION get_parent_domain_id(domain_name TEXT, tenant_id_param INTEGER) RETURNS INTEGER AS
$$
DECLARE
    parent_name  TEXT;
    parent_id    INTEGER;
    dot_position INTEGER;
BEGIN
    -- Skip for domains without dots
    IF domain_name = '.' OR position('.' IN domain_name) = 0 THEN
        RETURN NULL;
    END IF;

    -- Get the immediate parent by removing the leftmost part
    parent_name := substring(domain_name FROM position('.' IN domain_name) + 1);

    -- Try to find this parent in the database
    LOOP
        -- Look for the current parent_name in the database
        SELECT id
        INTO parent_id
        FROM domains
        WHERE name = parent_name
          AND tenant_id = tenant_id_param
        LIMIT 1;

        -- If we found a parent, return its ID
        IF parent_id IS NOT NULL THEN
            RETURN parent_id;
        END IF;

        -- If we didn't find it, try to get the next level up in the hierarchy
        dot_position := position('.' IN parent_name);

        -- If there are no more dots, we've reached the top level and found nothing
        IF dot_position = 0 THEN
            RETURN NULL;
        END IF;

        -- Get the next level up
        parent_name := substring(parent_name FROM dot_position + 1);
    END LOOP;
END;
$$ LANGUAGE plpgsql;;

-- Create a trigger to set parent_domain_id on insert or update
CREATE OR REPLACE FUNCTION set_parent_domain_id() RETURNS TRIGGER AS
$$
BEGIN
    -- Set the parent_domain_id based on the domain name
    NEW.parent_domain_id := get_parent_domain_id(NEW.name, NEW.tenant_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER domains_set_parent_id_trigger
    BEFORE INSERT OR UPDATE
    ON domains
    FOR EACH ROW
EXECUTE FUNCTION set_parent_domain_id();

-- Update existing domains to set parent_domain_id
DO
$$
    DECLARE
        domain_rec RECORD;
    BEGIN
        FOR domain_rec IN SELECT id, name, tenant_id FROM domains
            LOOP
                UPDATE domains
                SET parent_domain_id = get_parent_domain_id(domain_rec.name, domain_rec.tenant_id)
                WHERE id = domain_rec.id;
            END LOOP;
    END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS domains_set_parent_id_trigger ON domains;
DROP FUNCTION IF EXISTS set_parent_domain_id();
DROP FUNCTION IF EXISTS get_parent_domain_id(TEXT, INTEGER);
DROP INDEX IF EXISTS idx_domains_parent_domain_id;
ALTER TABLE domains
    DROP COLUMN IF EXISTS parent_domain_id;
-- +goose StatementEnd