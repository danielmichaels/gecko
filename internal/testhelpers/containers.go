package testhelpers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/danielmichaels/gecko/assets"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var TestLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelDebug,
}))

type PostgresContainer struct {
	*postgres.PostgresContainer
	Pool             *pgxpool.Pool
	Queries          *store.Queries
	ConnectionString string

	adminURL string
	dbName   string
}

// CreatePostgresContainer provisions an isolated Postgres database for a test.
// When TEST_DATABASE_URL is set (Dagger/CI), it creates a uniquely-named
// database on that shared server. Otherwise it spins up a throwaway container
// via testcontainers, which requires a local Docker daemon.
func CreatePostgresContainer(ctx context.Context) (*PostgresContainer, error) {
	if adminURL := os.Getenv("TEST_DATABASE_URL"); adminURL != "" {
		return createSharedDatabase(ctx, adminURL)
	}
	return createTestcontainer(ctx)
}

func createTestcontainer(ctx context.Context) (*PostgresContainer, error) {
	pgContainer, err := postgres.Run(
		ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("test-db"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.WithSQLDriver("pgx"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(15*time.Second),
		),
	)
	if err != nil {
		return nil, err
	}
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, err
	}
	pool, queries, err := prepareDatabase(ctx, connStr)
	if err != nil {
		return nil, err
	}
	return &PostgresContainer{
		PostgresContainer: pgContainer,
		ConnectionString:  connStr,
		Pool:              pool,
		Queries:           queries,
	}, nil
}

func createSharedDatabase(ctx context.Context, adminURL string) (*PostgresContainer, error) {
	dbName, err := randomDBName()
	if err != nil {
		return nil, err
	}
	if err := execAdmin(ctx, adminURL, "CREATE DATABASE "+dbName); err != nil {
		return nil, fmt.Errorf("failed to create test database: %w", err)
	}
	connStr, err := databaseURL(adminURL, dbName)
	if err != nil {
		return nil, err
	}
	pool, queries, err := prepareDatabase(ctx, connStr)
	if err != nil {
		return nil, err
	}
	return &PostgresContainer{
		ConnectionString: connStr,
		Pool:             pool,
		Queries:          queries,
		adminURL:         adminURL,
		dbName:           dbName,
	}, nil
}

func prepareDatabase(
	ctx context.Context,
	connStr string,
) (*pgxpool.Pool, *store.Queries, error) {
	if err := runMigrations(connStr); err != nil {
		return nil, nil, err
	}
	if err := loadTestData(ctx, connStr); err != nil {
		return nil, nil, err
	}
	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse pool config: %w", err)
	}
	poolConfig.MaxConnLifetime = 3 * time.Minute
	poolConfig.MaxConnIdleTime = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection pool: %w", err)
	}
	return pool, store.New(pool), nil
}

func randomDBName() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate test database name: %w", err)
	}
	return "test_" + hex.EncodeToString(b), nil
}

func databaseURL(adminURL, dbName string) (string, error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse TEST_DATABASE_URL: %w", err)
	}
	u.Path = "/" + dbName
	return u.String(), nil
}

func execAdmin(ctx context.Context, adminURL, query string) error {
	db, err := sql.Open("pgx", adminURL)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, query)
	return err
}

func runMigrations(connStr string) error {
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database for migrations: %w", err)
	}
	defer db.Close()

	// sql.Open is lazy and the container's forwarded port can briefly refuse
	// connections after the readiness log fires (a Docker Desktop port-forward
	// gap). Ping until it accepts so goose's first query doesn't fail the race.
	pingCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		if err := db.PingContext(pingCtx); err == nil {
			break
		}
		select {
		case <-pingCtx.Done():
			return fmt.Errorf("database not ready for migrations: %w", pingCtx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}

	goose.SetBaseFS(assets.EmbeddedAssets)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

func loadTestData(ctx context.Context, connStr string) error {
	possiblePaths := []string{
		"sql/tests/test-data.sql",       // From project root
		"../sql/tests/test-data.sql",    // From internal directory
		"../../sql/tests/test-data.sql", // From internal/testhelpers
	}

	var testData []byte
	var err error
	var foundPath string

	for _, path := range possiblePaths {
		testData, err = os.ReadFile(path)
		if err == nil {
			foundPath = path
			break
		}
	}

	if err != nil {
		cwd, _ := os.Getwd()
		slog.Info("Searching for test data file", "cwd", cwd)
		return fmt.Errorf("failed to read test data file from any path: %w", err)
	}

	slog.Info("Found test data file", "path", foundPath)
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database for loading test data: %w", err)
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, string(testData))
	if err != nil {
		return fmt.Errorf("failed to execute test data SQL: %w", err)
	}
	return nil
}

// Close releases the pool and tears down the database: it drops the per-test
// database in shared-server mode, or terminates the container in local mode.
func (pc *PostgresContainer) Close(ctx context.Context) {
	if pc.Pool != nil {
		pc.Pool.Close()
	}

	if pc.dbName != "" {
		if err := execAdmin(ctx, pc.adminURL, "DROP DATABASE IF EXISTS "+pc.dbName+" WITH (FORCE)"); err != nil {
			slog.Error("failed to drop test database", "db", pc.dbName, "err", err)
		}
		return
	}

	if pc.PostgresContainer != nil {
		if err := pc.Terminate(ctx); err != nil {
			slog.Error("failed to terminate container", "err", err)
		}
	}
}
