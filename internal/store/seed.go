package store

import (
	"context"
	"fmt"

	"github.com/danielmichaels/gecko/assets"
)

// devSeedPath is the embedded demo seed applied to a fresh embedded-Postgres
// database on `serve` startup (see cmd.maybeSeedOnStartup).
const devSeedPath = "seeds/dev-seed.sql"

// SeedDemo loads the embedded development demo data (one tenant + sample domains)
// into db. It is idempotent and intended only for the empty embedded-Postgres dev
// database; callers gate it on that. The whole file runs in one Exec — pgx uses
// the simple protocol for an argument-less query, which permits multiple
// statements.
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
