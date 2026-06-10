package auth

import (
	"context"
	"errors"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type localProvider struct {
	db         *store.Queries
	bcryptCost int
}

func newLocalProvider(db *store.Queries, bcryptCost int) *localProvider {
	return &localProvider{db: db, bcryptCost: normaliseCost(bcryptCost)}
}

func (p *localProvider) Name() string { return "local" }

// Authenticate verifies an email/password against user_credentials. Password
// verification happens before the status check so a non-active account is not
// distinguishable from a wrong password by timing, and all failure modes collapse
// to ErrInvalidCredentials except the explicit not-active case.
func (p *localProvider) Authenticate(ctx context.Context, c Credentials) (*Principal, error) {
	user, err := p.db.UserGetByEmail(ctx, c.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	cred, err := p.db.UserCredentialGetByUserID(ctx, user.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if err := VerifyPassword(cred.PasswordHash, c.Password); err != nil {
		return nil, ErrInvalidCredentials
	}
	if user.Status != store.UserStatusActive {
		return nil, ErrUserNotActive
	}
	return &Principal{
		UserID:   user.ID,
		TenantID: user.TenantID.Int32,
		Role:     string(user.Role),
		Email:    user.Email,
	}, nil
}

// HashPassword hashes a plaintext password for storage in user_credentials. Exposed
// as a package function (not on Provider) because only password-based flows — signup
// and accept-invite — need it; an OIDC user has no password.
func HashPassword(password string, cost int) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), normaliseCost(cost))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword reports whether plaintext matches a stored bcrypt hash. It
// returns a non-nil error on mismatch so callers can branch on success without
// inspecting bcrypt internals.
func VerifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func normaliseCost(cost int) int {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return bcrypt.DefaultCost
	}
	return cost
}
