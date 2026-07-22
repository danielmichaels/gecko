package testhelpers_test

import (
	"context"
	"os"
	"testing"

	"github.com/danielmichaels/gecko/internal/testhelpers"
)

// TestEmbeddedHarness proves CreatePostgresContainer's embedded branch yields a
// working, migrated per-test database with no Docker daemon. It downloads a PG
// binary on first run, so it is opt-in via GECKO_TEST_EMBEDDED_PG (the same flag
// that selects the embedded branch in the first place).
func TestEmbeddedHarness(t *testing.T) {
	if os.Getenv("GECKO_TEST_EMBEDDED_PG") == "" {
		t.Skip(
			"set GECKO_TEST_EMBEDDED_PG=1 to run the embedded harness test (downloads a PG binary)",
		)
	}
	// Force the embedded branch even if a shared server URL is present in the env.
	t.Setenv("TEST_DATABASE_URL", "")

	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create embedded db: %v", err)
	}
	defer pc.Close(ctx)

	var one int
	if err := pc.Pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query embedded db: %v", err)
	}
	if one != 1 {
		t.Errorf("SELECT 1 = %d, want 1", one)
	}
}
