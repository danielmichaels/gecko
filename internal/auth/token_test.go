package auth

import (
	"strings"
	"testing"
)

func TestGenerateToken_UniqueAndDecodable(t *testing.T) {
	seen := make(map[string]struct{})
	for range 100 {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if tok == "" {
			t.Fatal("GenerateToken returned empty string")
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("GenerateToken produced a duplicate: %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestHashToken_DeterministicAndHex(t *testing.T) {
	h1 := HashToken("hunter2")
	h2 := HashToken("hunter2")
	if h1 != h2 {
		t.Fatalf("HashToken not deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("HashToken length = %d, want 64 (sha256 hex)", len(h1))
	}
	if HashToken("hunter3") == h1 {
		t.Fatal("HashToken collided on different inputs")
	}
	// raw token must never equal its hash (we never store the raw)
	if HashToken("hunter2") == "hunter2" {
		t.Fatal("HashToken returned the input unchanged")
	}
}

func TestNewAPIKey_FormatAndHash(t *testing.T) {
	key, err := NewAPIKey()
	if err != nil {
		t.Fatalf("NewAPIKey: %v", err)
	}
	if !strings.HasPrefix(key.Raw, apiKeyScheme+"_") {
		t.Fatalf("raw key %q missing %q prefix", key.Raw, apiKeyScheme)
	}
	parts := strings.Split(key.Raw, "_")
	if len(parts) != 3 {
		t.Fatalf("raw key %q has %d parts, want 3", key.Raw, len(parts))
	}
	if parts[1] != key.Prefix {
		t.Fatalf("key.Prefix %q != raw prefix segment %q", key.Prefix, parts[1])
	}
	// secret must hash to the stored KeyHash; the secret itself is never stored
	if got := HashToken(parts[2]); got != key.KeyHash {
		t.Fatalf("KeyHash %q != HashToken(secret) %q", key.KeyHash, got)
	}
	if strings.Contains(key.Prefix, "_") || strings.Contains(parts[2], "_") {
		t.Fatal("api key segments must not contain the '_' delimiter (use hex, not base64url)")
	}
}

func TestParseAPIKey(t *testing.T) {
	key, _ := NewAPIKey()
	prefix, secret, err := ParseAPIKey(key.Raw)
	if err != nil {
		t.Fatalf("ParseAPIKey(valid): %v", err)
	}
	if prefix != key.Prefix {
		t.Fatalf("parsed prefix %q != %q", prefix, key.Prefix)
	}
	if HashToken(secret) != key.KeyHash {
		t.Fatal("parsed secret does not hash to KeyHash")
	}

	for _, bad := range []string{"", "gk", "gk_only", "xx_a_b", "gk__b", "gk_a_"} {
		if _, _, err := ParseAPIKey(bad); err == nil {
			t.Errorf("ParseAPIKey(%q) = nil error, want error", bad)
		}
	}
}
