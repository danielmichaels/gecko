package service

import (
	"strings"
	"testing"
)

// These builders interpolate user-controlled values (workspace name, inviter
// email) into HTML email bodies, so the HTML variant must escape them to prevent
// injection in webmail clients. The text/plain variant stays raw by design.

func TestInvitationEmail_EscapesHTMLBody(t *testing.T) {
	evilTenant := "<script>alert(1)</script>"
	evilInviter := "attacker<script>@evil.test"
	msg := invitationEmail("to@x.test", evilTenant, evilInviter, "https://app.test", "tok123")

	if strings.Contains(msg.HTML, "<script>") {
		t.Errorf("HTML body must not contain unescaped injected markup; got: %s", msg.HTML)
	}
	if !strings.Contains(msg.HTML, "&lt;script&gt;") {
		t.Errorf("HTML body should contain the escaped tenant name; got: %s", msg.HTML)
	}
	if !strings.Contains(msg.Text, evilTenant) {
		t.Errorf("text body should keep the raw value; got: %s", msg.Text)
	}
}

func TestWelcomeEmail_EscapesHTMLBody(t *testing.T) {
	evilTenant := "<img src=x onerror=alert(1)>"
	msg := welcomeEmail("to@x.test", evilTenant, "https://app.test")

	if strings.Contains(msg.HTML, "<img") {
		t.Errorf("HTML body must not contain unescaped injected markup; got: %s", msg.HTML)
	}
	if !strings.Contains(msg.Text, evilTenant) {
		t.Errorf("text body should keep the raw value; got: %s", msg.Text)
	}
}
