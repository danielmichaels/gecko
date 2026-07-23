package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/assets"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// MigrateUp applies all pending goose migrations against dsn using the embedded
// migration FS. It is idempotent: a second call with nothing pending is a no-op.
//
// The running binary does not migrate in production (an external entrypoint /
// `task db:migration:up` does); this exists for the embedded-Postgres dev path,
// which must migrate its own freshly-initialised database on startup. When logger
// is non-nil, goose output is routed through it.
func MigrateUp(dsn string, logger *slog.Logger) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("store.MigrateUp: open db: %w", err)
	}
	defer db.Close()

	if err := waitForDB(db); err != nil {
		return fmt.Errorf("store.MigrateUp: %w", err)
	}

	if logger != nil {
		goose.SetLogger(&gooseSlogBridge{l: logger})
	}
	goose.SetBaseFS(assets.EmbeddedAssets)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("store.MigrateUp: set dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("store.MigrateUp: run migrations: %w", err)
	}
	return nil
}

// waitForDB pings db until it accepts connections or 30s elapses — an embedded
// Postgres may still be finishing startup when MigrateUp is called.
func waitForDB(db *sql.DB) error {
	const maxRetries = 30
	for i := range maxRetries {
		if err := db.Ping(); err == nil {
			return nil
		}
		if i == maxRetries-1 {
			return fmt.Errorf("database not ready after %d attempts", maxRetries)
		}
		time.Sleep(time.Second)
	}
	return nil
}

// gooseSlogBridge routes goose's logger output through slog. Fatalf logs at Error
// rather than exiting the process — MigrateUp returns the error to its caller.
type gooseSlogBridge struct{ l *slog.Logger }

func (g *gooseSlogBridge) Printf(format string, v ...any) {
	g.l.Info(fmt.Sprintf(format, v...))
}

func (g *gooseSlogBridge) Fatalf(format string, v ...any) {
	g.l.Error(fmt.Sprintf(format, v...))
}
