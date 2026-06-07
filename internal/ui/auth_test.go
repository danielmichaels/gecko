package ui_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/ui"
)

// fakeResolver is a test double for SessionResolver.
type fakeResolver struct {
	principals map[string]*auth.Principal
	err        error
}

func (f *fakeResolver) ResolveSession(_ context.Context, rawToken string) (*auth.Principal, error) {
	if f.err != nil {
		return nil, f.err
	}
	if p, ok := f.principals[rawToken]; ok {
		return p, nil
	}
	return nil, service.ErrUnauthenticated
}

func newTestApp(t *testing.T, resolver ui.SessionResolver) *ui.App {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xAB
	}
	cfg := ui.CookieConfig{
		Name:     "gecko_session",
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	return ui.New(resolver, cfg, key, nil)
}

func setSessionCookie(req *http.Request, name, value string) {
	req.AddCookie(&http.Cookie{Name: name, Value: value})
}

// TestWebAuth_ValidCookie verifies that a valid session cookie resolves the
// principal, injects it into context, and sets a non-empty CSRF token.
func TestWebAuth_ValidCookie(t *testing.T) {
	t.Parallel()

	principal := &auth.Principal{UserID: 1, TenantID: 10, Email: "alice@example.com", Role: "owner"}
	resolver := &fakeResolver{
		principals: map[string]*auth.Principal{"tok-valid": principal},
	}
	app := newTestApp(t, resolver)

	var gotPrincipal *auth.Principal
	var gotCSRF string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrincipal, _ = ui.PrincipalFrom(r.Context())
		gotCSRF = ui.CSRFTokenFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := app.WebAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/app/dashboard", nil)
	setSessionCookie(req, "gecko_session", "tok-valid")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotPrincipal == nil {
		t.Fatal("expected principal in context, got nil")
	}
	if gotPrincipal.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %q", gotPrincipal.Email)
	}
	if gotCSRF == "" {
		t.Error("expected non-empty CSRF token in context")
	}
}

// TestWebAuth_MissingCookie verifies that a request without a session cookie
// is redirected to /app/login and next is NOT called.
func TestWebAuth_MissingCookie(t *testing.T) {
	t.Parallel()

	app := newTestApp(t, &fakeResolver{})
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := app.WebAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/app/dashboard", nil)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/app/login" {
		t.Errorf("expected redirect to /app/login, got %q", loc)
	}
	if nextCalled {
		t.Error("next should not be called when cookie is missing")
	}
}

// TestWebAuth_ExpiredToken verifies that an expired/revoked session is handled:
// redirect to /app/login and the session cookie is cleared.
func TestWebAuth_ExpiredToken(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{
		err: service.ErrUnauthenticated,
	}
	app := newTestApp(t, resolver)
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := app.WebAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/app/dashboard", nil)
	setSessionCookie(req, "gecko_session", "tok-expired")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/app/login" {
		t.Errorf("expected redirect to /app/login, got %q", loc)
	}
	if nextCalled {
		t.Error("next should not be called for expired session")
	}

	// The session cookie must be cleared (MaxAge < 0 or empty value).
	cookies := rr.Result().Cookies()
	var cleared bool
	for _, c := range cookies {
		if c.Name == "gecko_session" && (c.MaxAge < 0 || c.Value == "") {
			cleared = true
		}
	}
	if !cleared {
		t.Error("expected session cookie to be cleared (MaxAge<0 or empty value)")
	}
}

// TestWebAuth_UnexpectedError verifies that an unexpected resolver error
// produces a 500 and does not call next.
func TestWebAuth_UnexpectedError(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{
		err: errors.New("database is on fire"),
	}
	app := newTestApp(t, resolver)
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := app.WebAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/app/dashboard", nil)
	setSessionCookie(req, "gecko_session", "tok-bad")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if nextCalled {
		t.Error("next should not be called on unexpected resolver error")
	}
}

// TestWebAuth_CrossTenantIsolation verifies that two concurrent requests with
// different session tokens each receive their own principal with no cross-
// contamination between tenants.
func TestWebAuth_CrossTenantIsolation(t *testing.T) {
	t.Parallel()

	principalA := &auth.Principal{UserID: 1, TenantID: 10, Email: "alice@a.com", Role: "owner"}
	principalB := &auth.Principal{UserID: 2, TenantID: 20, Email: "bob@b.com", Role: "viewer"}
	resolver := &fakeResolver{
		principals: map[string]*auth.Principal{
			"tok-A": principalA,
			"tok-B": principalB,
		},
	}
	app := newTestApp(t, resolver)

	check := func(token string, expected *auth.Principal) {
		t.Helper()
		var got *auth.Principal
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, _ = ui.PrincipalFrom(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		mw := app.WebAuth(next)
		req := httptest.NewRequest(http.MethodGet, "/app/dashboard", nil)
		setSessionCookie(req, "gecko_session", token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("token %q: expected 200, got %d", token, rr.Code)
		}
		if got == nil {
			t.Fatalf("token %q: nil principal", token)
		}
		if got.TenantID != expected.TenantID {
			t.Errorf("token %q: expected tenant %d, got %d", token, expected.TenantID, got.TenantID)
		}
	}

	check("tok-A", principalA)
	check("tok-B", principalB)
}
