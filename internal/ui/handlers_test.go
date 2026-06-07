package ui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/danielmichaels/gecko/internal/ui"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ── shared test scheduler ─────────────────────────────────────────────────────

type noopScheduler struct {
	mu    sync.Mutex
	calls int
}

func (n *noopScheduler) Schedule(
	_ context.Context,
	_ pgx.Tx,
	_ *store.Queries,
	_ jobs.DomainScanTarget,
	_ store.DomainSource,
) (int64, error) {
	n.mu.Lock()
	n.calls++
	n.mu.Unlock()
	return 1, nil
}

// ── test harness ──────────────────────────────────────────────────────────────

// uiHarness holds everything a UI handler test needs.
type uiHarness struct {
	svc       *service.Service
	handler   http.Handler // root mux with /app mounted
	cookieCfg ui.CookieConfig
	csrfKey   []byte
	pc        *testhelpers.PostgresContainer
}

// newUIHarness builds a real Service + Handlers over a test Postgres container
// and returns an http.Handler with routes mounted at /app.
func newUIHarness(t *testing.T, pc *testhelpers.PostgresContainer) *uiHarness {
	t.Helper()

	cfg := config.AppConfig()
	cfg.Auth.BcryptCost = 4
	cfg.Auth.SessionTTL = 720 * time.Hour

	provider, err := auth.NewProvider(auth.Config{Provider: "local", BcryptCost: 4}, pc.Queries)
	if err != nil {
		t.Fatalf("new auth provider: %v", err)
	}

	svc := service.NewWithScheduler(
		cfg,
		slog.New(slog.DiscardHandler),
		pc.Queries,
		pc.Pool,
		&noopScheduler{},
		provider,
	)

	csrfKey := bytes.Repeat([]byte{0xBE, 0xEF}, 16)
	cookieCfg := ui.CookieConfig{
		Name:     "gecko_session",
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	app := ui.New(svc.AuthService(), cookieCfg, csrfKey, nil)
	h := ui.NewHandlers(svc, app, cookieCfg, nil)

	root := chi.NewRouter()
	root.Mount("/app", h.Routes())

	return &uiHarness{
		svc:       svc,
		handler:   root,
		cookieCfg: cookieCfg,
		csrfKey:   csrfKey,
		pc:        pc,
	}
}

// loginCookie signs up a user (if they don't exist yet) via Signup then
// Authenticate + MintSession and returns the raw session cookie value and the
// matching CSRF token.
func (h *uiHarness) loginCookie(
	t *testing.T,
	email, password string,
) (cookieValue, csrfToken string) {
	t.Helper()
	ctx := context.Background()
	svcAuth := h.svc.AuthService()

	// Signup if not already registered; ignore ErrConflict for idempotency.
	_, err := svcAuth.Signup(ctx, service.SignupParams{
		Email:    email,
		Password: password,
	})
	if err != nil && !isErrConflict(err) {
		t.Fatalf("loginCookie signup %s: %v", email, err)
	}

	p, err := svcAuth.Authenticate(ctx, email, password)
	if err != nil {
		t.Fatalf("loginCookie authenticate %s: %v", email, err)
	}

	raw, _, err := svcAuth.MintSession(ctx, p, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("loginCookie mint session %s: %v", email, err)
	}

	csrf := ui.ExportedCSRFToken(h.csrfKey, raw)
	return raw, csrf
}

func isErrConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "conflict")
}

// do issues a request against the handler and returns the recorder.
// If cookieValue is non-empty, the session cookie is attached.
// If csrfToken is non-empty, the X-CSRF-Token header is set.
func (h *uiHarness) do(
	t *testing.T,
	method, path string,
	body []byte,
	cookieValue, csrfToken string,
) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: h.cookieCfg.Name, Value: cookieValue})
	}
	if csrfToken != "" {
		req.Header.Set(ui.CSRFHeader, csrfToken)
	}
	if body != nil && (method == http.MethodPost || method == http.MethodPut) {
		req.Header.Set("Content-Type", "application/json")
	}

	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

// doDelete issues a DELETE request, placing the JSON signals in the URL query
// parameter per datastar's GET/DELETE convention.
func (h *uiHarness) doDelete(
	t *testing.T,
	path string,
	signals []byte,
	cookieValue, csrfToken string,
) *httptest.ResponseRecorder {
	t.Helper()
	url := path
	if signals != nil {
		url = path + "?datastar=" + string(signals)
	}
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: h.cookieCfg.Name, Value: cookieValue})
	}
	if csrfToken != "" {
		req.Header.Set(ui.CSRFHeader, csrfToken)
	}
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

// seedDomainForTenant inserts a domain row directly via Queries.
func seedDomainForTenant(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID int32,
	name string,
) store.DomainsInsertRow {
	t.Helper()
	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       name,
		DomainType: store.DomainTypeSubdomain,
		Source:     store.DomainSourceUserSupplied,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		t.Fatalf("seed domain %s for tenant %d: %v", name, tenantID, err)
	}
	return d
}

// tenantIDFor looks up the tenant ID for a registered user.
func tenantIDFor(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	email string,
) int32 {
	t.Helper()
	u, err := pc.Queries.UserGetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("tenantIDFor %s: %v", email, err)
	}
	return u.TenantID.Int32
}

// loginBody encodes datastar signals JSON for a POST /app/login request.
func loginBody(email, password string) []byte {
	b, _ := json.Marshal(map[string]string{"email": email, "password": password})
	return b
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestHandlerLogin_Get(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	rr := h.do(t, http.MethodGet, "/app/login", nil, "", "")

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /app/login: want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Sign in") {
		t.Error("GET /app/login: body should contain 'Sign in'")
	}
}

func TestHandlerLogin_Post_WrongPassword(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	// Register user first.
	h.loginCookie(t, "user@wrongpass.com", "correctpw")

	rr := h.do(t, http.MethodPost, "/app/login", loginBody("user@wrongpass.com", "wrongpw"), "", "")

	// Handler returns 200 with SSE error patch, not 401.
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /app/login wrong pw: want 200 (SSE), got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `id="login-error"`) {
		t.Errorf(
			"POST /app/login wrong pw: body should contain login-error element, got: %s",
			rr.Body.String(),
		)
	}
	// No session cookie must be set.
	for _, c := range rr.Result().Cookies() {
		if c.Name == h.cookieCfg.Name && c.MaxAge > 0 {
			t.Errorf("POST /app/login wrong pw: session cookie should not be set")
		}
	}
}

func TestHandlerLogin_Post_Success(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	// Register user.
	_, err = h.svc.AuthService().Signup(ctx, service.SignupParams{
		Email:    "loginok@example.com",
		Password: "secret123",
	})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}

	rr := h.do(
		t,
		http.MethodPost,
		"/app/login",
		loginBody("loginok@example.com", "secret123"),
		"",
		"",
	)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST /app/login ok: want 200 (SSE), got %d", rr.Code)
	}

	// A session cookie must be set.
	var sessionCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == h.cookieCfg.Name {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("POST /app/login ok: expected session Set-Cookie, got none")
	}
	if sessionCookie.Value == "" {
		t.Error("POST /app/login ok: session cookie value is empty")
	}

	// SSE body must contain a redirect to /app/domains.
	if !strings.Contains(rr.Body.String(), "/app/domains") {
		t.Errorf(
			"POST /app/login ok: body should redirect to /app/domains, got: %s",
			rr.Body.String(),
		)
	}
}

func TestHandlerDomains_Unauthenticated(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	rr := h.do(t, http.MethodGet, "/app/domains", nil, "", "")

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("GET /app/domains no cookie: want 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/app/login" {
		t.Errorf("GET /app/domains no cookie: want redirect to /app/login, got %q", loc)
	}
}

func TestHandlerRoot_RedirectsToDomains(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)

	for _, path := range []string{"/app", "/app/"} {
		rr := h.do(t, http.MethodGet, path, nil, "", "")
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("GET %s: want 303, got %d", path, rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "/app/domains" {
			t.Errorf("GET %s: want redirect to /app/domains, got %q", path, loc)
		}
	}
}

func TestHandlerDomains_Authenticated(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, _ := h.loginCookie(t, "domainslist@example.com", "pass1234")

	// Seed a domain directly.
	tid := tenantIDFor(t, ctx, pc, "domainslist@example.com")
	seedDomainForTenant(t, ctx, pc, tid, "myseeded.example.com")

	rr := h.do(t, http.MethodGet, "/app/domains", nil, cookie, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /app/domains authed: want 200, got %d\nbody: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Domains") {
		t.Error("GET /app/domains authed: body should contain 'Domains'")
	}
	if !strings.Contains(body, "myseeded.example.com") {
		t.Errorf(
			"GET /app/domains authed: body should contain seeded domain, got partial: %s",
			body[:min(200, len(body))],
		)
	}
}

func TestHandlerDomains_CSRF_MissingToken(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, _ := h.loginCookie(t, "csrfmiss@example.com", "pass1234")

	body, _ := json.Marshal(map[string]string{"newDomain": "newdomain.com"})
	// POST without X-CSRF-Token.
	rr := h.do(t, http.MethodPost, "/app/domains", body, cookie, "")

	if rr.Code != http.StatusForbidden {
		t.Fatalf("POST /app/domains no CSRF: want 403, got %d", rr.Code)
	}
}

func TestHandlerDomains_AddDomain_WithCSRF(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, csrf := h.loginCookie(t, "adddom@example.com", "pass1234")

	body, _ := json.Marshal(map[string]string{"newDomain": "added-by-test.example.com"})
	rr := h.do(t, http.MethodPost, "/app/domains", body, cookie, csrf)

	if rr.Code != http.StatusOK {
		t.Fatalf(
			"POST /app/domains add: want 200 (SSE), got %d\nbody: %s",
			rr.Code,
			rr.Body.String(),
		)
	}
	if !strings.Contains(rr.Body.String(), "added-by-test.example.com") {
		t.Errorf(
			"POST /app/domains add: SSE body should contain new domain name, got: %s",
			rr.Body.String(),
		)
	}
}

func TestHandlerDomains_DeleteDomain(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, csrf := h.loginCookie(t, "deletedom@example.com", "pass1234")

	tid := tenantIDFor(t, ctx, pc, "deletedom@example.com")
	d := seedDomainForTenant(t, ctx, pc, tid, "delete-me.example.com")

	rr := h.doDelete(t, "/app/domains/"+d.Uid, nil, cookie, csrf)

	if rr.Code != http.StatusOK {
		t.Fatalf(
			"DELETE /app/domains/%s: want 200 (SSE), got %d\nbody: %s",
			d.Uid,
			rr.Code,
			rr.Body.String(),
		)
	}
	// SSE body should reference the row id for removal.
	if !strings.Contains(rr.Body.String(), "domain-row-"+d.Uid) {
		t.Errorf(
			"DELETE /app/domains/%s: SSE body should contain 'domain-row-%s', got: %s",
			d.Uid,
			d.Uid,
			rr.Body.String(),
		)
	}

	// Verify domain is actually gone from DB.
	p, _ := h.svc.AuthService().Authenticate(ctx, "deletedom@example.com", "pass1234")
	_, getErr := h.svc.DomainsService().Get(ctx, p, d.Uid)
	if getErr == nil {
		t.Error("DELETE domain: domain still exists in DB after deletion")
	}
}

func TestHandlerDomainDetail(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, _ := h.loginCookie(t, "detail@example.com", "pass1234")

	tid := tenantIDFor(t, ctx, pc, "detail@example.com")
	d := seedDomainForTenant(t, ctx, pc, tid, "detail-domain.example.com")

	rr := h.do(t, http.MethodGet, "/app/domains/"+d.Uid, nil, cookie, "")

	if rr.Code != http.StatusOK {
		t.Fatalf(
			"GET /app/domains/%s: want 200, got %d\nbody: %s",
			d.Uid,
			rr.Code,
			rr.Body.String(),
		)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "detail-domain.example.com") {
		t.Errorf(
			"GET /app/domains/%s: body should contain domain name, got partial: %s",
			d.Uid,
			body[:min(300, len(body))],
		)
	}
	// Verify lazy-load attributes are present.
	if !strings.Contains(body, "data-on-intersect") {
		t.Errorf(
			"GET /app/domains/%s: body should contain data-on-intersect lazy-load attribute",
			d.Uid,
		)
	}
	if !strings.Contains(body, "/records") {
		t.Errorf("GET /app/domains/%s: body should contain /records lazy-load target", d.Uid)
	}
	if !strings.Contains(body, "/timeline") {
		t.Errorf("GET /app/domains/%s: body should contain /timeline lazy-load target", d.Uid)
	}
}

func TestHandlerRecordsFragment(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, _ := h.loginCookie(t, "records@example.com", "pass1234")

	tid := tenantIDFor(t, ctx, pc, "records@example.com")
	d := seedDomainForTenant(t, ctx, pc, tid, "records-domain.example.com")

	rr := h.do(t, http.MethodGet, "/app/domains/"+d.Uid+"/records", nil, cookie, "")

	if rr.Code != http.StatusOK {
		t.Fatalf(
			"GET /app/domains/%s/records: want 200, got %d\nbody: %s",
			d.Uid,
			rr.Code,
			rr.Body.String(),
		)
	}
	// SSE body should target records-content.
	if !strings.Contains(rr.Body.String(), "records-content") {
		t.Errorf(
			"GET /app/domains/%s/records: SSE body should target records-content, got: %s",
			d.Uid,
			rr.Body.String(),
		)
	}
}

func TestHandlerTimelineFragment(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, _ := h.loginCookie(t, "timeline@example.com", "pass1234")

	tid := tenantIDFor(t, ctx, pc, "timeline@example.com")
	d := seedDomainForTenant(t, ctx, pc, tid, "timeline-domain.example.com")

	rr := h.do(t, http.MethodGet, "/app/domains/"+d.Uid+"/timeline", nil, cookie, "")

	if rr.Code != http.StatusOK {
		t.Fatalf(
			"GET /app/domains/%s/timeline: want 200, got %d\nbody: %s",
			d.Uid,
			rr.Code,
			rr.Body.String(),
		)
	}
	if !strings.Contains(rr.Body.String(), "timeline-content") {
		t.Errorf(
			"GET /app/domains/%s/timeline: SSE body should target timeline-content, got: %s",
			d.Uid,
			rr.Body.String(),
		)
	}
}

func TestHandlerComingSoon_Findings(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, _ := h.loginCookie(t, "findings@example.com", "pass1234")

	rr := h.do(t, http.MethodGet, "/app/findings", nil, cookie, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /app/findings: want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "On the roadmap") {
		t.Errorf(
			"GET /app/findings: body should contain 'On the roadmap', got partial: %s",
			rr.Body.String()[:min(300, len(rr.Body.String()))],
		)
	}
}

func TestHandlerLogout(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, csrf := h.loginCookie(t, "logout@example.com", "pass1234")

	rr := h.do(t, http.MethodPost, "/app/logout", nil, cookie, csrf)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST /app/logout: want 200 (SSE), got %d\nbody: %s", rr.Code, rr.Body.String())
	}
	// SSE body must redirect to /app/login.
	if !strings.Contains(rr.Body.String(), "/app/login") {
		t.Errorf(
			"POST /app/logout: SSE body should redirect to /app/login, got: %s",
			rr.Body.String(),
		)
	}
	// Session cookie must be cleared (MaxAge == -1).
	var cleared bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == h.cookieCfg.Name && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("POST /app/logout: session cookie must be cleared (MaxAge < 0)")
	}
	// Session must be revoked: resolving the old token must fail.
	_, resolveErr := h.svc.AuthService().ResolveSession(ctx, cookie)
	if resolveErr == nil {
		t.Error(
			"POST /app/logout: session should be revoked after logout but ResolveSession succeeded",
		)
	}
}

func TestHandlerCrossTenant_DomainDetail(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)

	// Tenant A.
	cookieA, _ := h.loginCookie(t, "tenant-a@cross.com", "pass1234")

	// Tenant B: sign up separately, seed their domain.
	h.loginCookie(t, "tenant-b@cross.com", "pass5678")
	tidB := tenantIDFor(t, ctx, pc, "tenant-b@cross.com")
	dB := seedDomainForTenant(t, ctx, pc, tidB, "b-private.example.com")

	// Tenant A requests Tenant B's domain detail.
	rr := h.do(t, http.MethodGet, "/app/domains/"+dB.Uid, nil, cookieA, "")

	// Must redirect to /app/domains (not found → redirect) — never show B's domain.
	if rr.Code != http.StatusSeeOther {
		t.Fatalf(
			"cross-tenant GET detail: want 303 redirect, got %d\nbody: %s",
			rr.Code,
			rr.Body.String(),
		)
	}
	if loc := rr.Header().Get("Location"); loc != "/app/domains" {
		t.Errorf("cross-tenant GET detail: want redirect to /app/domains, got %q", loc)
	}
	if strings.Contains(rr.Body.String(), "b-private.example.com") {
		t.Error("cross-tenant GET detail: response must not contain tenant B's domain name")
	}
}

func TestHandlerCrossTenant_DeleteDomain(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)

	cookieA, csrfA := h.loginCookie(t, "del-a@cross.com", "pass1234")
	h.loginCookie(t, "del-b@cross.com", "pass5678")
	tidB := tenantIDFor(t, ctx, pc, "del-b@cross.com")
	dB := seedDomainForTenant(t, ctx, pc, tidB, "b-cant-delete.example.com")

	// A tries to delete B's domain.
	rr := h.doDelete(t, "/app/domains/"+dB.Uid, nil, cookieA, csrfA)

	// Handler is idempotent for not-found; it still returns 200 SSE (no error status).
	if rr.Code != http.StatusOK {
		t.Fatalf("cross-tenant DELETE: want 200 (SSE idempotent), got %d", rr.Code)
	}

	// B's domain must still exist in the DB.
	pB, err := h.svc.AuthService().Authenticate(ctx, "del-b@cross.com", "pass5678")
	if err != nil {
		t.Fatalf("authenticate tenant B: %v", err)
	}
	got, err := h.svc.DomainsService().Get(ctx, pB, dB.Uid)
	if err != nil {
		t.Errorf("cross-tenant DELETE: B's domain should still exist, got: %v", err)
	}
	if got.Name != "b-cant-delete.example.com" {
		t.Errorf("cross-tenant DELETE: unexpected domain name %q", got.Name)
	}
}

func TestHandlerCrossTenant_RecordsFragment(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)

	cookieA, _ := h.loginCookie(t, "rec-a@cross.com", "pass1234")
	h.loginCookie(t, "rec-b@cross.com", "pass5678")
	tidB := tenantIDFor(t, ctx, pc, "rec-b@cross.com")
	dB := seedDomainForTenant(t, ctx, pc, tidB, "b-records-private.example.com")

	rr := h.do(t, http.MethodGet, "/app/domains/"+dB.Uid+"/records", nil, cookieA, "")

	// Handler returns 200 with SSE content-error (not-found), never tenant B's data.
	if rr.Code != http.StatusOK {
		t.Fatalf("cross-tenant records: want 200 (SSE), got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "b-records-private.example.com") {
		t.Error("cross-tenant records: response must not contain tenant B's domain name")
	}
	// Should contain the error element, not blank data.
	if !strings.Contains(body, "records-content") {
		t.Errorf("cross-tenant records: SSE body should target records-content, got: %s", body)
	}
}

func TestHandlerCrossTenant_TimelineFragment(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)

	cookieA, _ := h.loginCookie(t, "tl-a@cross.com", "pass1234")
	h.loginCookie(t, "tl-b@cross.com", "pass5678")
	tidB := tenantIDFor(t, ctx, pc, "tl-b@cross.com")
	dB := seedDomainForTenant(t, ctx, pc, tidB, "b-timeline-private.example.com")

	rr := h.do(t, http.MethodGet, "/app/domains/"+dB.Uid+"/timeline", nil, cookieA, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("cross-tenant timeline: want 200 (SSE), got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "b-timeline-private.example.com") {
		t.Error("cross-tenant timeline: response must not contain tenant B's domain name")
	}
	if !strings.Contains(body, "timeline-content") {
		t.Errorf("cross-tenant timeline: SSE body should target timeline-content, got: %s", body)
	}
}

func TestHandlerInvite_Get_NoToken(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	rr := h.do(t, http.MethodGet, "/app/invite", nil, "", "")

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /app/invite no token: want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Invalid Invitation") {
		t.Error("GET /app/invite no token: body should contain 'Invalid Invitation'")
	}
}

func TestHandlerInvite_Get_ValidToken(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	// Sign up an owner who will invite.
	h.loginCookie(t, "inviter@example.com", "pass1234")
	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "inviter@example.com")
	if err != nil {
		t.Fatalf("lookup owner: %v", err)
	}

	// Seed a valid invitation.
	rawToken, genErr := auth.GenerateToken()
	if genErr != nil {
		t.Fatalf("generate token: %v", genErr)
	}
	_, err = pc.Queries.InvitationCreate(ctx, store.InvitationCreateParams{
		TenantID:  ownerUser.TenantID.Int32,
		Email:     "invitee@example.com",
		Role:      store.UserRoleViewer,
		TokenHash: auth.HashToken(rawToken),
		InvitedBy: pgtype.Int4{Int32: ownerUser.ID, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatalf("seed invitation: %v", err)
	}

	rr := h.do(t, http.MethodGet, "/app/invite?token="+rawToken, nil, "", "")

	if rr.Code != http.StatusOK {
		t.Fatalf(
			"GET /app/invite valid token: want 200, got %d\nbody: %s",
			rr.Code,
			rr.Body.String(),
		)
	}
	// Accept-invite page should contain the invitee context.
	body := rr.Body.String()
	if !strings.Contains(body, "invitee@example.com") {
		t.Errorf(
			"GET /app/invite valid: body should contain invitee email, got partial: %s",
			body[:min(400, len(body))],
		)
	}
}

func TestHandlerInvite_Post_InvalidToken(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)

	body, _ := json.Marshal(map[string]string{
		"token":    "bogus-invite-token",
		"password": "newpassword",
		"name":     "",
	})
	rr := h.do(t, http.MethodPost, "/app/invite", body, "", "")

	if rr.Code != http.StatusOK {
		t.Fatalf("POST /app/invite invalid token: want 200 (SSE), got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `id="invite-error"`) {
		t.Errorf(
			"POST /app/invite invalid token: body should contain invite-error, got: %s",
			rr.Body.String(),
		)
	}
}

func TestHandlerInvite_Post_Valid(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	h.loginCookie(t, "inviter2@example.com", "pass1234")
	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "inviter2@example.com")
	if err != nil {
		t.Fatalf("lookup owner: %v", err)
	}

	rawToken, genErr := auth.GenerateToken()
	if genErr != nil {
		t.Fatalf("generate token: %v", genErr)
	}
	_, err = pc.Queries.InvitationCreate(ctx, store.InvitationCreateParams{
		TenantID:  ownerUser.TenantID.Int32,
		Email:     "newinvitee@example.com",
		Role:      store.UserRoleViewer,
		TokenHash: auth.HashToken(rawToken),
		InvitedBy: pgtype.Int4{Int32: ownerUser.ID, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatalf("seed invitation: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"token":    rawToken,
		"password": "newpassword123",
		"name":     "New Invitee",
	})
	rr := h.do(t, http.MethodPost, "/app/invite", body, "", "")

	if rr.Code != http.StatusOK {
		t.Fatalf(
			"POST /app/invite valid: want 200 (SSE), got %d\nbody: %s",
			rr.Code,
			rr.Body.String(),
		)
	}
	// A session cookie must be set.
	var sessionCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == h.cookieCfg.Name {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("POST /app/invite valid: expected session Set-Cookie, got none")
	}
	// SSE must redirect to /app/domains.
	if !strings.Contains(rr.Body.String(), "/app/domains") {
		t.Errorf(
			"POST /app/invite valid: SSE body should redirect to /app/domains, got: %s",
			rr.Body.String(),
		)
	}
}

func TestHandlerDomainRescan_NotFound(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, csrf := h.loginCookie(t, "rescan@example.com", "pass1234")

	const nonExistentUID = "uid-does-not-exist-xyz"
	rr := h.do(t, http.MethodPost, "/app/domains/"+nonExistentUID+"/rescan", nil, cookie, csrf)

	// Handler opens SSE and patches an error element — still 200.
	if rr.Code != http.StatusOK {
		t.Fatalf(
			"POST /app/domains/%s/rescan: want 200 (SSE error), got %d",
			nonExistentUID,
			rr.Code,
		)
	}
	body := rr.Body.String()
	// Should contain the rescan-status error patch (not-found text).
	if !strings.Contains(body, "rescan-status") {
		t.Errorf(
			"POST /app/domains/%s/rescan: SSE body should contain rescan-status error, got: %s",
			nonExistentUID,
			body,
		)
	}
}

func TestHandlerRescanAll_RoutesCorrectly(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, csrf := h.loginCookie(t, "rescanall@example.com", "pass1234")

	// POST /app/domains/rescan must hit the rescan-all handler, not a uid="rescan" handler.
	rr := h.do(t, http.MethodPost, "/app/domains/rescan", nil, cookie, csrf)

	// Rescan-all returns 200 whether there are domains or not.
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /app/domains/rescan: want 200, got %d\nbody: %s", rr.Code, rr.Body.String())
	}
}

// min is a small helper to avoid panics when slicing body for error messages.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
