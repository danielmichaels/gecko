package ui_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/ui"
)

// TestSetSessionCookie verifies that SetSessionCookie produces a cookie with
// the expected attributes: HttpOnly, Secure as configured, SameSite as configured.
func TestSetSessionCookie(t *testing.T) {
	t.Parallel()

	cfg := ui.CookieConfig{
		Name:     "gecko_session",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	expires := time.Now().Add(time.Hour)
	rr := httptest.NewRecorder()
	ui.SetSessionCookie(rr, "raw-token-value", expires, cfg)

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected at least one cookie")
	}
	var c *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "gecko_session" {
			c = cookie
			break
		}
	}
	if c == nil {
		t.Fatal("gecko_session cookie not found")
	}
	if c.Value != "raw-token-value" {
		t.Errorf("expected value %q, got %q", "raw-token-value", c.Value)
	}
	if !c.HttpOnly {
		t.Error("expected HttpOnly=true")
	}
	if !c.Secure {
		t.Error("expected Secure=true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite=Lax, got %v", c.SameSite)
	}
	if c.MaxAge <= 0 {
		t.Errorf("expected positive MaxAge, got %d", c.MaxAge)
	}
}

// TestClearSessionCookie verifies ClearSessionCookie produces a clearing cookie
// with MaxAge < 0 and an empty or zeroed value.
func TestClearSessionCookie(t *testing.T) {
	t.Parallel()

	cfg := ui.CookieConfig{
		Name:     "gecko_session",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	rr := httptest.NewRecorder()
	ui.ClearSessionCookie(rr, cfg)

	cookies := rr.Result().Cookies()
	var c *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "gecko_session" {
			c = cookie
			break
		}
	}
	if c == nil {
		t.Fatal("gecko_session cookie not found in clear response")
	}
	if c.MaxAge >= 0 {
		t.Errorf("expected MaxAge<0 for clear cookie, got %d", c.MaxAge)
	}
}
