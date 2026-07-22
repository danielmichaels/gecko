package embeddedpg_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/embeddedpg"
	"github.com/jackc/pgx/v5/pgxpool"
)

// requireEmbeddedPG gates the tests that boot a real embedded Postgres: they
// download a ~15MB PG binary from Maven Central on first run, so they stay off
// by default (short mode, and Gecko's Dagger CI which runs without -short).
// Opt in locally with GECKO_TEST_EMBEDDED_PG=1.
func requireEmbeddedPG(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping embedded-postgres test in short mode (requires binary download)")
	}
	if os.Getenv("GECKO_TEST_EMBEDDED_PG") == "" {
		t.Skip(
			"set GECKO_TEST_EMBEDDED_PG=1 to run embedded-postgres tests (downloads a PG binary)",
		)
	}
}

func TestStart_PingAndStop(t *testing.T) {
	requireEmbeddedPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	srv, err := embeddedpg.Start(embeddedpg.Options{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := srv.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	pool, err := pgxpool.New(ctx, srv.DSN)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestStart_ParallelNoPorts(t *testing.T) {
	requireEmbeddedPG(t)

	start := func(t *testing.T) *embeddedpg.Server {
		t.Helper()
		srv, err := embeddedpg.Start(embeddedpg.Options{})
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		return srv
	}

	a := start(t)
	b := start(t)
	defer a.Stop() //nolint:errcheck
	defer b.Stop() //nolint:errcheck

	if a.DSN == b.DSN {
		t.Errorf("parallel instances got the same DSN: %s", a.DSN)
	}
}
