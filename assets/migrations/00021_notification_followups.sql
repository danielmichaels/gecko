-- +goose Up
-- +goose StatementBegin
-- Notification follow-ups: per-user opt-out, a separate opt-in toggle for
-- near-real-time high-impact alerts, and that path's own watermark.
--
--   users.notify_opt_out                    : per-user kill-switch. A user opts
--       themselves out of all notification email regardless of the tenant toggles.
--       Default false (in), so existing recipients are unaffected.
--   tenant_settings.notify_high_impact_alerts : opt-IN (default false) for the
--       frequent critical/high alert sweep. Distinct from notify_high_impact, which
--       only controls the highlighted section inside the daily digest — immediate
--       email is more intrusive, so it is off until a tenant asks for it.
--   tenant_settings.notifications_last_alert_at : the alert sweep's watermark,
--       independent of the digest watermark so the two cadences never interfere.
ALTER TABLE users
    ADD COLUMN notify_opt_out BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE tenant_settings
    ADD COLUMN notify_high_impact_alerts    BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN notifications_last_alert_at  TIMESTAMPTZ;

-- Seed the alert watermark like the digest one so the first sweep after a tenant
-- opts in reports only go-forward findings, not the whole backlog.
UPDATE tenant_settings
SET notifications_last_alert_at = now();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tenant_settings
    DROP COLUMN IF EXISTS notifications_last_alert_at,
    DROP COLUMN IF EXISTS notify_high_impact_alerts;
ALTER TABLE users
    DROP COLUMN IF EXISTS notify_opt_out;
-- +goose StatementEnd
