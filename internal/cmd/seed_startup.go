package cmd

import (
	"fmt"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/store"
)

// maybeSeedOnStartup loads demo data when running against a fresh embedded
// database. It runs before owner auto-bootstrap so the bootstrapped owner adopts
// the seeded tenant (bootstrapOwner takes the lowest-id tenant). It is a no-op
// unless embedded mode is active (config.ShouldSeedOnStartup) and the database is
// empty — the empty check keeps `air` hot-reload restarts from reseeding.
func maybeSeedOnStartup(setup *Setup) error {
	if !config.ShouldSeedOnStartup(setup.Config) {
		return nil
	}
	var tenantCount int64
	row := setup.PgxPool.QueryRow(setup.Ctx, "SELECT count(*) FROM tenants")
	if err := row.Scan(&tenantCount); err != nil {
		return fmt.Errorf("check existing seed data: %w", err)
	}
	if tenantCount > 0 {
		setup.Logger.Info("seed data present, skipping startup seed", "tenants", tenantCount)
		return nil
	}
	setup.Logger.Info("empty embedded database detected, seeding demo data")
	return store.SeedDemo(setup.Ctx, setup.PgxPool)
}
