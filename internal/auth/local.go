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
	// Role and tenant live on memberships now, not the user row. Pick the user's
	// default active tenant; a user with no membership cannot establish a session.
	memberships, err := p.db.MembershipsListForUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	def, ok := DefaultMembership(memberships)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	return &Principal{
		UserID:   user.ID,
		TenantID: def.TenantID,
		Role:     string(def.Role),
		Email:    user.Email,
	}, nil
}

// DefaultMembership picks the active tenant for a freshly authenticated user from
// their memberships: an owner role wins, otherwise the earliest-joined tenant. It
// reports false when the user belongs to no tenant. The caller can switch tenants
// afterwards; this only chooses where they land first.
func DefaultMembership(
	memberships []store.MembershipsListForUserRow,
) (store.MembershipsListForUserRow, bool) {
	var best store.MembershipsListForUserRow
	found := false
	for _, m := range memberships {
		if !found {
			best, found = m, true
			continue
		}
		bestOwner := best.Role == store.UserRoleOwner
		mOwner := m.Role == store.UserRoleOwner
		switch {
		case mOwner && !bestOwner:
			best = m
		case mOwner == bestOwner && m.CreatedAt.Time.Before(best.CreatedAt.Time):
			best = m
		}
	}
	return best, found
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
