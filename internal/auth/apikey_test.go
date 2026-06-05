package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// validRow builds a key row whose secret matches `secret` and which passes every
// gate, so each test can knock out one condition at a time.
func validRow(secret string) store.ApiKeyGetByPrefixRow {
	return store.ApiKeyGetByPrefixRow{
		ID:         1,
		Uid:        "apikey_00000001",
		TenantID:   7,
		UserID:     42,
		KeyHash:    HashToken(secret),
		ExpiresAt:  pgtype.Timestamptz{}, // NULL == never expires
		RevokedAt:  pgtype.Timestamptz{}, // NULL == not revoked
		UserEmail:  "owner@example.com",
		UserRole:   store.UserRoleOwner,
		UserStatus: store.UserStatusActive,
	}
}

func TestVerifyKeyRow_Valid(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p, err := verifyKeyRow(validRow("s3cret"), "s3cret", now)
	if err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if p.UserID != 42 || p.TenantID != 7 || p.Role != "owner" || p.Email != "owner@example.com" {
		t.Fatalf("principal = %+v, want {42 7 owner owner@example.com}", p)
	}
}

func TestVerifyKeyRow_Rejections(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	past := pgtype.Timestamptz{Time: now.Add(-time.Hour), Valid: true}
	future := pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true}

	t.Run("wrong secret", func(t *testing.T) {
		if _, err := verifyKeyRow(validRow("right"), "wrong", now); !errors.Is(
			err,
			ErrInvalidAPIKey,
		) {
			t.Fatalf("err = %v, want ErrInvalidAPIKey", err)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		row := validRow("s")
		row.RevokedAt = past
		if _, err := verifyKeyRow(row, "s", now); !errors.Is(err, ErrInvalidAPIKey) {
			t.Fatalf("err = %v, want ErrInvalidAPIKey", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		row := validRow("s")
		row.ExpiresAt = past
		if _, err := verifyKeyRow(row, "s", now); !errors.Is(err, ErrInvalidAPIKey) {
			t.Fatalf("err = %v, want ErrInvalidAPIKey", err)
		}
	})
	t.Run("not yet expired is allowed", func(t *testing.T) {
		row := validRow("s")
		row.ExpiresAt = future
		if _, err := verifyKeyRow(row, "s", now); err != nil {
			t.Fatalf("future-expiry key rejected: %v", err)
		}
	})
	t.Run("inactive user", func(t *testing.T) {
		row := validRow("s")
		row.UserStatus = store.UserStatusInactive
		if _, err := verifyKeyRow(row, "s", now); !errors.Is(err, ErrInvalidAPIKey) {
			t.Fatalf("err = %v, want ErrInvalidAPIKey", err)
		}
	})
}
