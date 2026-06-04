package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/danielmichaels/gecko/internal/store"
)

// Config carries the auth knobs the package needs, decoupled from the application
// config struct so this package never imports internal/config.
type Config struct {
	Provider   string
	BcryptCost int
}

// Credentials is a username/password pair presented for authentication.
type Credentials struct {
	Email    string
	Password string
}

// Provider authenticates credentials into a Principal. The local provider checks a
// password; a future OIDC provider verifies an identity-token instead — handlers
// depend only on this interface.
type Provider interface {
	Name() string
	Authenticate(ctx context.Context, c Credentials) (*Principal, error)
}

var (
	// ErrInvalidCredentials is returned for any failed login. It is deliberately
	// opaque — it never distinguishes "no such user" from "wrong password" from
	// "no credentials row" — so callers cannot probe which emails are registered.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserNotActive is returned when credentials are valid but the user's status
	// is not 'active'.
	ErrUserNotActive = errors.New("user is not active")
)

// NewProvider selects an auth provider by name. "local" (the default) authenticates
// against user_credentials; "oidc" is a not-yet-implemented seam.
func NewProvider(cfg Config, db *store.Queries) (Provider, error) {
	switch cfg.Provider {
	case "", "local":
		return newLocalProvider(db, cfg.BcryptCost), nil
	case "oidc":
		return newOIDCProvider(), nil
	default:
		return nil, fmt.Errorf("unknown auth provider %q", cfg.Provider)
	}
}
