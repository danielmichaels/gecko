package store_test

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

func TestMigrateUp_Idempotent(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
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
