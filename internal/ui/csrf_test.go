package ui_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/ui"
)

// TestCSRFToken_Determinism verifies same-inputs produce same output and
// different keys produce different outputs.
func TestCSRFToken_Determinism(t *testing.T) {
	t.Parallel()

	keyA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
	keyB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	raw := "session-token-abc"

	t1 := ui.ExportedCSRFToken(keyA, raw)
	t2 := ui.ExportedCSRFToken(keyA, raw)
	if t1 != t2 {
		t.Errorf("same key+raw should produce the same token: got %q vs %q", t1, t2)
	}

	t3 := ui.ExportedCSRFToken(keyB, raw)
	if t1 == t3 {
		t.Errorf("different keys should produce different tokens; both returned %q", t1)
	}
}

// TestCSRF_SafeMethodsPass verifies GET/HEAD pass without a CSRF token header.
func TestCSRF_SafeMethodsPass(t *testing.T) {
	t.Parallel()

	principal := &auth.Principal{UserID: 1, TenantID: 10, Email: "alice@a.com", Role: "owner"}
	resolver := &fakeResolver{
		principals: map[string]*auth.Principal{"tok": principal},
	}
	app := newTestApp(t, resolver)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})
			handler := app.WebAuth(app.CSRFValidate(next))
			req := httptest.NewRequest(method, "/app/dashboard", nil)
			setSessionCookie(req, "gecko_session", "tok")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("%s: expected 200, got %d", method, rr.Code)
			}
			if !nextCalled {
				t.Errorf("%s: next should be called for safe methods", method)
			}
		})
	}
}

// TestCSRF_PostMissingHeader verifies that POST without X-CSRF-Token → 403.
func TestCSRF_PostMissingHeader(t *testing.T) {
	t.Parallel()

	principal := &auth.Principal{UserID: 1, TenantID: 10, Email: "alice@a.com", Role: "owner"}
	resolver := &fakeResolver{
		principals: map[string]*auth.Principal{"tok": principal},
	}
	app := newTestApp(t, resolver)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := app.WebAuth(app.CSRFValidate(next))
	req := httptest.NewRequest(http.MethodPost, "/app/action", nil)
	setSessionCookie(req, "gecko_session", "tok")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

// TestCSRF_PostWrongToken verifies that POST with a wrong X-CSRF-Token → 403.
func TestCSRF_PostWrongToken(t *testing.T) {
	t.Parallel()

	principal := &auth.Principal{UserID: 1, TenantID: 10, Email: "alice@a.com", Role: "owner"}
	resolver := &fakeResolver{
		principals: map[string]*auth.Principal{"tok": principal},
	}
	app := newTestApp(t, resolver)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := app.WebAuth(app.CSRFValidate(next))
	req := httptest.NewRequest(http.MethodPost, "/app/action", nil)
	setSessionCookie(req, "gecko_session", "tok")
	req.Header.Set(ui.CSRFHeader, "totally-wrong-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

// TestCSRF_PostCorrectToken verifies that POST with the correct X-CSRF-Token passes.
func TestCSRF_PostCorrectToken(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xAB
	}
	principal := &auth.Principal{UserID: 1, TenantID: 10, Email: "alice@a.com", Role: "owner"}
	resolver := &fakeResolver{
		principals: map[string]*auth.Principal{"tok-sess": principal},
	}
	cfg := ui.CookieConfig{
		Name:     "gecko_session",
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	app := ui.New(resolver, cfg, key, nil)

	// Compute the expected token the same way the middleware does.
	expected := ui.ExportedCSRFToken(key, "tok-sess")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := app.WebAuth(app.CSRFValidate(next))
	req := httptest.NewRequest(http.MethodPost, "/app/action", nil)
	setSessionCookie(req, "gecko_session", "tok-sess")
	req.Header.Set(ui.CSRFHeader, expected)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !nextCalled {
		t.Error("next should be called when CSRF token matches")
	}
}

// TestCSRF_ContextTokenConsistency verifies the token injected into context
// equals ExportedCSRFToken(key, rawToken).
func TestCSRF_ContextTokenConsistency(t *testing.T) {
	t.Parallel()

	key := []byte("consistent-key-for-testing-12345")
	rawToken := "tok-consistent"

	principal := &auth.Principal{UserID: 1, TenantID: 10, Email: "alice@a.com", Role: "owner"}
	resolver := &fakeResolver{
		principals: map[string]*auth.Principal{rawToken: principal},
	}
	cfg := ui.CookieConfig{
		Name:     "gecko_session",
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	app := ui.New(resolver, cfg, key, nil)

	var contextCSRF string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextCSRF = ui.CSRFTokenFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	mw := app.WebAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/app/dashboard", nil)
	setSessionCookie(req, "gecko_session", rawToken)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	expected := ui.ExportedCSRFToken(key, rawToken)
	if contextCSRF != expected {
		t.Errorf("context CSRF %q does not match expected %q", contextCSRF, expected)
	}
}
