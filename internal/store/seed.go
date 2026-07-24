package store

import (
	"context"
	"fmt"

	"github.com/danielmichaels/gecko/assets"
)

const devSeedPath = "seeds/dev-seed.sql"

func SeedDemo(ctx context.Context, db DBTX) error {
	sqlBytes, err := assets.EmbeddedAssets.ReadFile(devSeedPath)
	if err != nil {
		return fmt.Errorf("store.SeedDemo: read %s: %w", devSeedPath, err)
	}
	if _, err := db.Exec(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("store.SeedDemo: apply seed: %w", err)
	}
	return nil
}
