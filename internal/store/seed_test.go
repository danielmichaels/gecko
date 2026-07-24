package store_test

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

func TestSeedDemo(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer pc.Close(ctx)

	if err := store.SeedDemo(ctx, pc.Pool); err != nil {
		t.Fatalf("SeedDemo: %v", err)
	}
	if err := store.SeedDemo(ctx, pc.Pool); err != nil {
		t.Fatalf("SeedDemo second run (idempotency): %v", err)
	}

	var domains int
	if err := pc.Pool.QueryRow(
		ctx,
		"SELECT count(*) FROM domains WHERE uid LIKE 'domain_demo%'",
	).Scan(&domains); err != nil {
		t.Fatalf("count demo domains: %v", err)
	}
	if domains != 2 {
		t.Errorf("demo domains = %d, want 2", domains)
	}
}
