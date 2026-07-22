package store_test

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

// TestMigrateUp_Idempotent runs against the harness's already-migrated per-test
// database, so MigrateUp must be a clean no-op — this exercises the goose wiring
// (embedded FS + dialect) against a real Postgres and proves re-running is safe.
func TestMigrateUp_Idempotent(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer pc.Close(ctx)

	if err := store.MigrateUp(pc.ConnectionString, nil); err != nil {
		t.Fatalf("MigrateUp on migrated db: %v", err)
	}
	if err := store.MigrateUp(pc.ConnectionString, nil); err != nil {
		t.Fatalf("MigrateUp second run: %v", err)
	}
}
