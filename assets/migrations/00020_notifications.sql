-- +goose Up
-- +goose StatementBegin
-- Notifications layer (daily digest, email-first). The toggles live on
-- tenant_settings — already the one-row-per-tenant settings home (00019) with an
-- updated_at trigger — rather than a new table: there is no per-channel config to
-- store yet, and a separate table would buy only a join. Per-channel rows
-- (Slack/webhook tokens) get their own table when that ships; the on/off booleans
-- stay here.
--
--   notify_daily_digest          : opt-out master switch for the daily summary email.
--   notify_high_impact           : opt-out flag for the highlighted critical/high
--                                  section (also the seam for phase-2 real-time alerts).
--   notifications_last_digest_at : per-tenant watermark. The digest window is
--                                  exactly (notifications_last_digest_at, now]; the
--                                  column advances transactionally with the send, so
--                                  a late/retried tick never double-counts and a
--                                  skipped tick never drops changes. NULL = never
--                                  sent (first run uses a bounded fallback window).
ALTER TABLE tenant_settings
    ADD COLUMN notify_daily_digest          BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN notify_high_impact           BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN notifications_last_digest_at  TIMESTAMPTZ;

-- Seed the watermark for existing tenants to now() so the first digest after deploy
-- reports only go-forward changes rather than dumping the full backlog. Every
-- existing tenant already has a tenant_settings row (00019 backfill). New tenants
-- get NULL and are bounded by the fallback window on their first eligible tick.
UPDATE tenant_settings
SET notifications_last_digest_at = now();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tenant_settings
    DROP COLUMN IF EXISTS notifications_last_digest_at,
    DROP COLUMN IF EXISTS notify_high_impact,
    DROP COLUMN IF EXISTS notify_daily_digest;
-- +goose StatementEnd
