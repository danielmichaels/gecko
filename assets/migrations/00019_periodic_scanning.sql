-- +goose Up
-- +goose StatementBegin
-- Cadence presets for periodic scanning. 'off' disables scheduled scans. On
-- domains.scan_frequency, NULL means "inherit the tenant default".
CREATE TYPE scan_frequency AS ENUM ('hourly', 'six_hourly', 'daily', 'weekly', 'off');

-- A scan's trigger is a superset of a domain's origin: a scan can be 'scheduled'
-- but a domain can only ever be 'user_supplied' or 'discovered'. Splitting the
-- type (rather than adding 'scheduled' to domain_source) makes the illegal state
-- — a scheduled-origin domain — unrepresentable.
CREATE TYPE scan_source AS ENUM ('user_supplied', 'discovered', 'scheduled');

-- Per-tenant configuration; one row per tenant. The default cadence is inherited
-- by any domain whose scan_frequency override is NULL. Opt-out model: new tenants
-- default to daily.
CREATE TABLE IF NOT EXISTS tenant_settings
(
    tenant_id              INTEGER PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    default_scan_frequency scan_frequency NOT NULL DEFAULT 'daily',
    created_at             TIMESTAMPTZ    NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ    NOT NULL DEFAULT now()
);
CREATE TRIGGER trigger_updated_at_tenant_settings
    BEFORE UPDATE
    ON tenant_settings
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

-- Periodic-scan scheduling columns on domains.
--   scan_frequency  : per-domain override; NULL = inherit tenant default.
--   next_scan_at    : materialized scheduling cursor; NULL when effective freq is 'off'.
--   last_scanned_at : real last-scan stamp (replaces the updated_at proxy in the UI).
ALTER TABLE domains
    ADD COLUMN scan_frequency  scan_frequency,
    ADD COLUMN next_scan_at    TIMESTAMPTZ,
    ADD COLUMN last_scanned_at TIMESTAMPTZ;

-- Partial index: the due-query (status='active' AND next_scan_at <= now()) is an
-- index range scan. 'off' domains have next_scan_at = NULL and fall out of the
-- index entirely, so a paused domain costs the scheduler nothing.
CREATE INDEX idx_domains_next_scan_at ON domains (next_scan_at)
    WHERE status = 'active' AND next_scan_at IS NOT NULL;

-- Swap scans.source from domain_source to scan_source. Existing values
-- ('user_supplied','discovered') are a strict subset of the new type, so the
-- text round-trip preserves every row; no value is rewritten.
ALTER TABLE scans
    ALTER COLUMN source DROP DEFAULT;
ALTER TABLE scans
    ALTER COLUMN source TYPE scan_source USING source::text::scan_source;
ALTER TABLE scans
    ALTER COLUMN source SET DEFAULT 'user_supplied'::scan_source;

-- Backfill (opt-out): every existing tenant gets a daily default; every active
-- domain enters the schedule jittered across the next 24h so the first tick after
-- deploy does not herd. Overrides stay NULL (inherit).
INSERT INTO tenant_settings (tenant_id)
SELECT id
FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;

UPDATE domains
SET next_scan_at = now() + (random() * interval '24 hours')
WHERE status = 'active';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Reverse the scans.source type swap. Safe only while no row holds 'scheduled'
-- (true until the scheduled worker ships). If rolling back after scheduled scans
-- exist, remap them first:
--   UPDATE scans SET source = 'discovered' WHERE source = 'scheduled';
ALTER TABLE scans
    ALTER COLUMN source DROP DEFAULT;
ALTER TABLE scans
    ALTER COLUMN source TYPE domain_source USING source::text::domain_source;
ALTER TABLE scans
    ALTER COLUMN source SET DEFAULT 'user_supplied'::domain_source;

DROP INDEX IF EXISTS idx_domains_next_scan_at;
ALTER TABLE domains
    DROP COLUMN IF EXISTS last_scanned_at,
    DROP COLUMN IF EXISTS next_scan_at,
    DROP COLUMN IF EXISTS scan_frequency;
DROP TABLE IF EXISTS tenant_settings;
DROP TYPE IF EXISTS scan_source;
DROP TYPE IF EXISTS scan_frequency;
-- +goose StatementEnd
