package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

// newAuthAPI builds a real Server over the test container and serves it via httptest
// so requests exercise the full chi → huma → apiAuth → handler chain. RC is nil; the
// auth/read/delete paths under test never enqueue a job.
func newAuthAPI(t *testing.T, pc *testhelpers.PostgresContainer) (*Server, string) {
	t.Helper()
	cfg := config.AppConfig()
	cfg.Auth.BcryptCost = 4 // fast hashing for tests
	cfg.Auth.SignupEnabled = true
	provider, err := auth.NewProvider(auth.Config{Provider: "local", BcryptCost: 4}, pc.Queries)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	svc := service.NewWithScheduler(cfg, slog.New(slog.DiscardHandler), pc.Queries, pc.Pool, nil)
	app := &Server{
		Conf:         cfg,
		Log:          slog.New(slog.DiscardHandler),
		Db:           pc.Queries,
		PgxPool:      pc.Pool,
		AuthProvider: provider,
		Svc:          svc,
	}
	srv := httptest.NewServer(app.routes())
	t.Cleanup(srv.Close)
	return app, srv.URL
}

// doJSON performs an HTTP request with an optional API key and JSON body, decoding a
// success response into out (if non-nil). It returns the status code.
func doJSON(t *testing.T, method, url, apiKey string, body, out any) int {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
	return resp.StatusCode
}

type tokenResp struct {
	APIKey    string `json:"api_key"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	TenantUID string `json:"tenant_uid"`
}

func signup(t *testing.T, base, email, password string) tokenResp {
	t.Helper()
	var out tokenResp
	code := doJSON(t, http.MethodPost, base+"/api/auth/signup", "",
		map[string]string{"email": email, "password": password}, &out)
	if code != http.StatusCreated {
		t.Fatalf("signup %s: status %d", email, code)
	}
	if out.APIKey == "" {
		t.Fatalf("signup %s: empty api key", email)
	}
	return out
}

func tenantIDByEmail(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	email string,
) int32 {
	t.Helper()
	u, err := pc.Queries.UserGetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("lookup tenant for %s: %v", email, err)
	}
	return u.TenantID.Int32
}

func seedDomain(
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
		t.Fatalf("seed domain %s: %v", name, err)
	}
	return d
}

func TestAuth_SignupLoginMe(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	tok := signup(t, base, "owner@team-a.com", "supersecret")
	if tok.Role != "owner" {
		t.Errorf("signup role = %q, want owner", tok.Role)
	}

	// /me with the signup key
	var me struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if code := doJSON(t, http.MethodGet, base+"/api/auth/me", tok.APIKey, nil, &me); code != http.StatusOK {
		t.Fatalf("me: status %d", code)
	}
	if me.Email != "owner@team-a.com" || me.Role != "owner" {
		t.Errorf("me = %+v", me)
	}

	// login returns a (different) working key
	var login tokenResp
	if code := doJSON(t, http.MethodPost, base+"/api/auth/login", "",
		map[string]string{"email": "owner@team-a.com", "password": "supersecret"}, &login); code != http.StatusOK {
		t.Fatalf("login: status %d", code)
	}
	if login.APIKey == "" || login.APIKey == tok.APIKey {
		t.Errorf("login should mint a fresh key")
	}

	// wrong password → 401
	if code := doJSON(t, http.MethodPost, base+"/api/auth/login", "",
		map[string]string{"email": "owner@team-a.com", "password": "wrong"}, nil); code != http.StatusUnauthorized {
		t.Errorf("bad login status = %d, want 401", code)
	}

	// duplicate email → 409
	if code := doJSON(t, http.MethodPost, base+"/api/auth/signup", "",
		map[string]string{"email": "owner@team-a.com", "password": "supersecret"}, nil); code != http.StatusConflict {
		t.Errorf("duplicate signup status = %d, want 409", code)
	}
}

func TestAuth_SignupDisabled(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	app, base := newAuthAPI(t, pc)
	app.Conf.Auth.SignupEnabled = false

	if code := doJSON(t, http.MethodPost, base+"/api/auth/signup", "",
		map[string]string{"email": "x@y.com", "password": "supersecret"}, nil); code != http.StatusForbidden {
		t.Errorf("signup-disabled status = %d, want 403", code)
	}
}

func TestAuth_MissingOrInvalidKey(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	if code := doJSON(t, http.MethodGet, base+"/api/auth/me", "", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("no key status = %d, want 401", code)
	}
	if code := doJSON(t, http.MethodGet, base+"/api/auth/me", "gk_deadbeef_bogus", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("bad key status = %d, want 401", code)
	}
	if code := doJSON(t, http.MethodGet, base+"/api/auth/me", "not-even-a-key", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("malformed key status = %d, want 401", code)
	}
}
