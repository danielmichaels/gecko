package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// apiKeyScheme is the human-recognisable prefix on every API key (gk = gecko key).
const apiKeyScheme = "gk"

const (
	apiKeyPrefixBytes = 4  // 8 hex chars — the non-secret lookup id
	apiKeySecretBytes = 32 // 64 hex chars — the secret
	tokenBytes        = 32
)

// ErrMalformedAPIKey is returned when a raw key is not a well-formed gk_<prefix>_<secret>.
var ErrMalformedAPIKey = errors.New("malformed api key")

// GenerateToken returns a URL-safe random opaque token (raw, unhashed). Used for
// invitations, which are looked up by hash and never split, so the base64url
// alphabet is safe here.
func GenerateToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the hex sha256 of a raw token for at-rest storage and lookup.
// The raw value is never persisted.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// APIKey is a freshly minted key. Raw is shown to the user exactly once; only
// Prefix and KeyHash are persisted.
type APIKey struct {
	Raw     string
	Prefix  string
	KeyHash string
}

// NewAPIKey mints a key of the form gk_<prefix>_<secret>. Both random segments are
// hex-encoded so they cannot contain the '_' delimiter.
func NewAPIKey() (APIKey, error) {
	prefix, err := randHex(apiKeyPrefixBytes)
	if err != nil {
		return APIKey{}, err
	}
	secret, err := randHex(apiKeySecretBytes)
	if err != nil {
		return APIKey{}, err
	}
	return APIKey{
		Raw:     apiKeyScheme + "_" + prefix + "_" + secret,
		Prefix:  prefix,
		KeyHash: HashToken(secret),
	}, nil
}

// ParseAPIKey splits a raw key into its prefix (lookup id) and secret. It does not
// validate the secret — callers compare HashToken(secret) against the stored hash.
func ParseAPIKey(raw string) (prefix, secret string, err error) {
	parts := strings.Split(raw, "_")
	if len(parts) != 3 || parts[0] != apiKeyScheme || parts[1] == "" || parts[2] == "" {
		return "", "", ErrMalformedAPIKey
	}
	return parts[1], parts[2], nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
