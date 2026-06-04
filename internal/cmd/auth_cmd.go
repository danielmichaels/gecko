package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"gopkg.in/yaml.v3"
)

type AuthCmd struct {
	Login     LoginCmd     `cmd:"" help:"Login to gecko server"`
	Logout    LogoutCmd    `cmd:"" help:"Logout from gecko server"`
	Status    StatusCmd    `cmd:"" help:"Show authentication status"`
	Bootstrap BootstrapCmd `cmd:"" help:"Create the first owner + tenant directly in the database"`
}

type authTokenResponse struct {
	APIKey    string     `json:"api_key"`
	ExpiresAt *time.Time `json:"expires_at"`
	Email     string     `json:"email"`
	Role      string     `json:"role"`
	TenantUID string     `json:"tenant_uid"`
}

type LoginCmd struct{}

// Run exchanges email/password for an API key and persists it to the YAML config so
// subsequent commands authenticate via X-API-Key.
func (l *LoginCmd) Run(g *Globals, ac *AuthCmd) error {
	if g.ServerURL == "" {
		return fmt.Errorf("server-url is required")
	}
	if g.Username == "" {
		return fmt.Errorf("username (email) is required for login")
	}
	if g.Password == "" {
		return fmt.Errorf("password is required for login")
	}
	ctx, cancel := createCancellableContext()
	defer cancel()

	var out authTokenResponse
	var apiErr huma.ErrorModel
	err := requests.
		URL(g.ServerURL+"/api/auth/login").
		BodyJSON(map[string]string{"email": g.Username, "password": g.Password}).
		ToJSON(&out).
		ErrorJSON(&apiErr).
		Fetch(ctx)
	if err != nil {
		if apiErr.Status != 0 {
			return handleHumaError(apiErr)
		}
		return err
	}

	config := map[string]any{
		"server-url": g.ServerURL,
		"api-key":    out.APIKey,
	}
	if out.ExpiresAt != nil {
		config["expires-at"] = out.ExpiresAt.Format(time.RFC3339)
	}
	yamlData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(string(g.ConfigFile), yamlData, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	fmt.Printf("Logged in to %s as %s\n", g.ServerURL, out.Email)
	return nil
}

type LogoutCmd struct{}

// Run revokes the current API key server-side (best-effort) and clears it locally.
func (l *LogoutCmd) Run(g *Globals, ac *AuthCmd) error {
	if g.ServerURL != "" && g.APIKey != "" {
		ctx, cancel := createCancellableContext()
		defer cancel()
		var apiErr huma.ErrorModel
		_ = requestWithSpinner(ctx, g, "Logging out...", func() *requests.Builder {
			return requests.
				URL(g.ServerURL + "/api/auth/logout").
				Method(http.MethodPost).
				ErrorJSON(&apiErr)
		})
	}
	config := map[string]any{"server-url": g.ServerURL}
	yamlData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(string(g.ConfigFile), yamlData, 0o600); err != nil {
		return fmt.Errorf("failed to clear config file: %w", err)
	}
	fmt.Println("Logged out")
	return nil
}

type StatusCmd struct{}

// Run reports the identity behind the configured API key.
func (s *StatusCmd) Run(g *Globals, ac *AuthCmd) error {
	if err := validateAPIAccess(g); err != nil {
		return err
	}
	ctx, cancel := createCancellableContext()
	defer cancel()

	var out struct {
		Email    string `json:"email"`
		Role     string `json:"role"`
		UserID   int32  `json:"user_id"`
		TenantID int32  `json:"tenant_id"`
	}
	var apiErr huma.ErrorModel
	err := requestWithSpinner(ctx, g, "Checking status...", func() *requests.Builder {
		return requests.
			URL(g.ServerURL + "/api/auth/me").
			ToJSON(&out).
			ErrorJSON(&apiErr)
	})
	if err != nil {
		if apiErr.Status != 0 {
			return handleHumaError(apiErr)
		}
		return err
	}
	fmt.Printf("Logged in as %s (role: %s)\n", out.Email, out.Role)
	return nil
}

type BootstrapCmd struct {
	Email      string `required:"" help:"Owner email address"`
	Password   string `required:"" help:"Owner password"`
	TenantName string `name:"tenant-name" default:"default" help:"Tenant name to use if no tenant exists yet"`
}

// Run creates (idempotently) the first owner and credentials directly in the
// database, adopting the existing tenant if one is present. Intended to make a
// pre-auth single-tenant install reachable, or to seed a fresh install.
func (b *BootstrapCmd) Run(g *Globals) error {
	setup, err := NewSetup("bootstrap", WithSilentLogging())
	if err != nil {
		return err
	}
	defer setup.Close()

	ctx := setup.Ctx
	q := setup.Store
	email := strings.ToLower(strings.TrimSpace(b.Email))

	// Adopt the existing tenant (lowest id) so current single-tenant data becomes
	// reachable; create one only if the install has none.
	var tenantID int32
	err = setup.PgxPool.QueryRow(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 1`).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		t, cerr := q.TenantCreate(ctx, b.TenantName)
		if cerr != nil {
			return fmt.Errorf("create tenant: %w", cerr)
		}
		tenantID = t.ID
	} else if err != nil {
		return fmt.Errorf("look up tenant: %w", err)
	}

	var userID int32
	existing, err := q.UserGetByEmail(ctx, email)
	switch {
	case err == nil:
		userID = existing.ID
	case errors.Is(err, pgx.ErrNoRows):
		u, perr := q.UserProvision(ctx, store.UserProvisionParams{
			TenantID: pgtype.Int4{Int32: tenantID, Valid: true},
			Email:    email,
			Role:     store.UserRoleOwner,
		})
		if perr != nil {
			return fmt.Errorf("provision owner: %w", perr)
		}
		userID = u.ID
	default:
		return fmt.Errorf("look up user: %w", err)
	}

	hash, err := auth.HashPassword(b.Password, setup.Config.Auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := q.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       userID,
		PasswordHash: hash,
	}); err != nil {
		return fmt.Errorf("set credentials: %w", err)
	}

	fmt.Printf("Bootstrapped owner %s on tenant id=%d\n", email, tenantID)
	return nil
}
