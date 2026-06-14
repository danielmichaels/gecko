package templates_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/ui/templates"
)

func settingsProps(canManage bool, keys []templates.APIKeyRowView) templates.SettingsPageProps {
	return templates.SettingsPageProps{
		Shell: templates.AppShellProps{
			UserEmail: "owner@acme.io",
			ActiveNav: "settings",
			CSRFToken: "tok",
		},
		APIKeys:   keys,
		CanManage: canManage,
	}
}

func TestSettingsPage_ManagerSeesControls(t *testing.T) {
	var buf bytes.Buffer
	keys := []templates.APIKeyRowView{
		{
			UID:      "apikey_1",
			Name:     "ci",
			Prefix:   "gk_abcd1234",
			Created:  "2d ago",
			LastUsed: "1h ago",
			Expires:  "never",
		},
	}
	if err := templates.SettingsPage(settingsProps(true, keys)).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "/app/settings/apikeys") {
		t.Error("expected create-key POST target for a manager")
	}
	if !strings.Contains(out, "gk_abcd1234") {
		t.Error("expected the key prefix in the list")
	}
	// Revoke control present for an active key, carrying the CSRF header. The uid
	// is JSON-encoded and concatenated, so it appears as a quoted JS literal next
	// to the endpoint path rather than inlined into it.
	if !strings.Contains(out, "@delete(") ||
		!strings.Contains(out, "/app/settings/apikeys/") ||
		!strings.Contains(out, "apikey_1") {
		t.Error("expected revoke action for the active key")
	}
	if !strings.Contains(out, "X-CSRF-Token") {
		t.Error("expected CSRF header in the key actions")
	}
	// Password form posts to the password endpoint.
	if !strings.Contains(out, "/app/settings/password") {
		t.Error("expected password-change POST target")
	}
}

func TestSettingsPage_ViewerHidesControls(t *testing.T) {
	var buf bytes.Buffer
	keys := []templates.APIKeyRowView{
		{
			UID:      "apikey_1",
			Name:     "ci",
			Prefix:   "gk_abcd1234",
			Created:  "2d ago",
			LastUsed: "—",
			Expires:  "never",
		},
	}
	if err := templates.SettingsPage(settingsProps(false, keys)).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "/app/settings/apikeys") {
		t.Error("viewer must not see the create-key control")
	}
	if strings.Contains(out, "/app/settings/apikeys") {
		t.Error("viewer must not see the revoke control")
	}
	// The viewer still sees the key list (read-only).
	if !strings.Contains(out, "gk_abcd1234") {
		t.Error("viewer should still see the key list")
	}
}

func TestSettingsPage_RevokedKeyHasNoRevokeControl(t *testing.T) {
	var buf bytes.Buffer
	keys := []templates.APIKeyRowView{
		{
			UID:      "apikey_dead",
			Name:     "old",
			Prefix:   "gk_dead0000",
			Created:  "9d ago",
			LastUsed: "—",
			Expires:  "never",
			Revoked:  true,
		},
	}
	if err := templates.SettingsPage(settingsProps(true, keys)).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "revoked") {
		t.Error("expected a 'revoked' badge for the revoked key")
	}
	// The only revoke action on this page would be for this key; a revoked key must
	// render none.
	if strings.Contains(out, "@delete(") {
		t.Error("a revoked key must not offer a revoke control")
	}
}

func TestAPIKeyRow_MaliciousNameCannotBreakOutOfJS(t *testing.T) {
	var buf bytes.Buffer
	// A name crafted to terminate the confirm() string literal and inject a
	// statement. After the fix the name is JSON-encoded into a double-quoted JS
	// string, so its single quotes can no longer close the confirm() literal.
	evil := "x');alert(document.cookie);('"
	if err := templates.APIKeyRow(
		templates.APIKeyRowView{UID: "apikey_1", Name: evil, Prefix: "gk_x"},
		"tok",
		true,
	).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	// The injected payload must be confined inside a JSON-encoded ("double-quoted")
	// JS string. templ escapes the wrapping double-quotes to &#34;, so the encoded
	// name appears between &#34; markers rather than bare inside the confirm()
	// single-quotes.
	if !strings.Contains(out, "&#34;x&#39;);alert(document.cookie);(&#39;&#34;") {
		t.Errorf("malicious key name was not JSON-encoded into a JS string literal; got:\n%s", out)
	}
}

func TestSettingsPage_NotificationsToggles(t *testing.T) {
	var buf bytes.Buffer
	props := settingsProps(true, nil)
	props.NotifyDailyDigest = true
	props.NotifyHighImpact = false
	props.NotifyHighImpactAlerts = true
	props.NotifyOptOut = false
	props.LastDigestSent = "2026-06-14 08:00 UTC"
	props.LastAlertSent = "never"
	if err := templates.SettingsPage(props).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "/app/settings/notifications&#39;") {
		t.Error("expected the tenant notifications save POST target for a manager")
	}
	for _, sig := range []string{"notifyDailyDigest", "notifyHighImpact", "notifyHighImpactAlerts", "notifyOptOut"} {
		if !strings.Contains(out, sig) {
			t.Errorf("expected %q toggle bound to a signal", sig)
		}
	}
	// The page-level signal object reflects the tenant's current toggle state so the
	// checkboxes render pre-checked/unchecked. The data-signals attribute is
	// HTML-escaped, so the JSON quotes appear as &#34;.
	if !strings.Contains(out, `notifyDailyDigest&#34;:true`) ||
		!strings.Contains(out, `notifyHighImpact&#34;:false`) ||
		!strings.Contains(out, `notifyHighImpactAlerts&#34;:true`) {
		t.Errorf("expected signals to seed current toggle state; got:\n%s", out)
	}
	// Last-sent timestamps are surfaced.
	if !strings.Contains(out, "2026-06-14 08:00 UTC") {
		t.Error("expected the last-digest-sent timestamp to be shown")
	}
	// The personal mute save is available to everyone.
	if !strings.Contains(out, "/app/settings/notifications/me") {
		t.Error("expected the personal opt-out save target")
	}
}

func TestSettingsPage_NotificationsViewerHidesTenantSave(t *testing.T) {
	var buf bytes.Buffer
	if err := templates.SettingsPage(settingsProps(false, nil)).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	// The viewer must not see the tenant-wide save, but must still see the personal
	// opt-out save (self-service) and the toggles (read-only state).
	if strings.Contains(out, "/app/settings/notifications&#39;") {
		t.Error("viewer must not see the tenant notifications save control")
	}
	if !strings.Contains(out, "/app/settings/notifications/me") {
		t.Error("viewer should still see the personal opt-out save")
	}
	if !strings.Contains(out, "notifyDailyDigest") {
		t.Error("viewer should still see the notification toggles")
	}
}

func TestSettingsPage_EmptyKeyList(t *testing.T) {
	var buf bytes.Buffer
	if err := templates.SettingsPage(settingsProps(true, nil)).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "No API keys yet") {
		t.Error("expected empty-state message when there are no keys")
	}
}

func TestAPIKeySecret_ShowsRawOnceWithCopy(t *testing.T) {
	var buf bytes.Buffer
	if err := templates.APIKeySecret(templates.APIKeySecretView{
		Name: "ci",
		Raw:  "gk_abcd1234_secretsecretsecret",
	}).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "gk_abcd1234_secretsecretsecret") {
		t.Error("expected the plaintext secret in the reveal")
	}
	if !strings.Contains(out, "shown once") {
		t.Error("expected the one-time warning")
	}
	if !strings.Contains(out, "navigator.clipboard.writeText") {
		t.Error("expected a copy affordance")
	}
}
