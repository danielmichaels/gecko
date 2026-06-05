package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
)

// ErrInvalidAPIKey is returned for every API-key rejection — malformed, unknown
// prefix, wrong secret, revoked, expired, or owned by a non-active user. It is
// deliberately opaque so a caller cannot tell which condition failed.
var ErrInvalidAPIKey = errors.New("invalid api key")

// APIKeyStore is the slice of the data layer that key verification needs.
// *store.Queries satisfies it.
type APIKeyStore interface {
	ApiKeyGetByPrefix(ctx context.Context, prefix string) (store.ApiKeyGetByPrefixRow, error)
	ApiKeyTouchLastUsed(ctx context.Context, id int32) error
}

// VerifyAPIKey resolves a raw "gk_<prefix>_<secret>" key to a Principal. It looks
// the key up by its non-secret prefix, applies the security gate in verifyKeyRow,
// and (best-effort) records last-used. It returns the Principal and the key's uid
// (so logout can revoke exactly this key).
func VerifyAPIKey(ctx context.Context, db APIKeyStore, raw string) (*Principal, string, error) {
	prefix, secret, err := ParseAPIKey(raw)
	if err != nil {
		return nil, "", ErrInvalidAPIKey
	}
	row, err := db.ApiKeyGetByPrefix(ctx, prefix)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrInvalidAPIKey
		}
		return nil, "", err
	}
	p, err := verifyKeyRow(row, secret, time.Now())
	if err != nil {
		return nil, "", err
	}
	_ = db.ApiKeyTouchLastUsed(ctx, row.ID)
	return p, row.Uid, nil
}

// verifyKeyRow applies the security gate to a fetched key row and returns the
// caller's Principal, or ErrInvalidAPIKey if the key must be rejected. The secret
// is compared in constant time (timing must not reveal the stored hash); a NULL
// ExpiresAt means the key never expires; every rejection returns the same opaque
// error so callers cannot tell which check failed.
func verifyKeyRow(
	row store.ApiKeyGetByPrefixRow,
	secret string,
	now time.Time,
) (*Principal, error) {
	if subtle.ConstantTimeCompare([]byte(HashToken(secret)), []byte(row.KeyHash)) != 1 {
		return nil, ErrInvalidAPIKey
	}
	if row.RevokedAt.Valid {
		return nil, ErrInvalidAPIKey
	}
	if row.ExpiresAt.Valid && !row.ExpiresAt.Time.After(now) {
		return nil, ErrInvalidAPIKey
	}
	if row.UserStatus != store.UserStatusActive {
		return nil, ErrInvalidAPIKey
	}
	return &Principal{
		UserID:   row.UserID,
		TenantID: row.TenantID,
		Role:     string(row.UserRole),
		Email:    row.UserEmail,
	}, nil
}
