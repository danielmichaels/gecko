package testhelpers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"hash"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/danielmichaels/gecko/assets"
	"github.com/danielmichaels/gecko/internal/embeddedpg"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

var TestLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelDebug,
}))

type TestDatabase struct {
	Pool             *pgxpool.Pool
	Queries          *store.Queries
	ConnectionString string

	releaseShared func()
	adminURL      string
	dbName        string
}

type sharedTemplateState struct {
	err  error
	name string
	once sync.Once
}

var (
	sharedTemplatesMu sync.Mutex
	sharedTemplates   = map[string]*sharedTemplateState{}

	sharedEmbeddedMu     sync.Mutex
	sharedEmbedded       *embeddedpg.Server
	sharedEmbeddedURL    string
	sharedEmbeddedUsers  int
	sharedEmbeddedSerial int
)

// CreateTestDatabase provisions an isolated Postgres database for a test by
// cloning a migrated template database. By default it boots one shared in-process
// embedded Postgres for the test binary (no Docker required); set TEST_DATABASE_URL
// to run against an external server instead (Dagger/CI, or an explicit local one).
func CreateTestDatabase(ctx context.Context) (*TestDatabase, error) {
	if adminURL := os.Getenv("TEST_DATABASE_URL"); adminURL != "" {
		return createSharedDatabase(ctx, adminURL)
	}
	return createSharedEmbeddedDatabase(ctx)
}

// ParallelDBTest opts a DB-backed test into parallel execution. CreateTestDatabase
// keeps per-test database isolation by cloning a migrated template database.
type parallelTest interface {
	Helper()
	Parallel()
}

func ParallelDBTest(t parallelTest) {
	t.Helper()
	t.Parallel()
}

func createSharedEmbeddedDatabase(ctx context.Context) (*TestDatabase, error) {
	adminURL, release, err := sharedEmbeddedAdminURL()
	if err != nil {
		return nil, err
	}
	pc, err := createSharedDatabase(ctx, adminURL)
	if err != nil {
		release()
		return nil, err
	}
	pc.releaseShared = release
	return pc, nil
}

// sharedEmbeddedAdminURL boots a single embedded Postgres for the whole test
// binary and hands out its admin URL, refcounted so the instance is stopped (and
// its temp data dir removed) when the last test releases it.
func sharedEmbeddedAdminURL() (string, func(), error) {
	sharedEmbeddedMu.Lock()
	defer sharedEmbeddedMu.Unlock()

	if sharedEmbedded == nil {
		srv, err := embeddedpg.Start(embeddedpg.Options{})
		if err != nil {
			return "", nil, err
		}
		sharedEmbedded = srv
		sharedEmbeddedURL = srv.DSN
		sharedEmbeddedSerial++
	}

	sharedEmbeddedUsers++
	released := false
	serial := sharedEmbeddedSerial
	release := func() {
		sharedEmbeddedMu.Lock()
		defer sharedEmbeddedMu.Unlock()
		if released {
			return
		}
		released = true
		sharedEmbeddedUsers--
		if sharedEmbeddedUsers != 0 || sharedEmbedded == nil || sharedEmbeddedSerial != serial {
			return
		}
		if err := sharedEmbedded.Stop(); err != nil {
			slog.Error("failed to stop shared embedded postgres", "err", err)
		}
		sharedTemplatesMu.Lock()
		for key := range sharedTemplates {
			if strings.HasPrefix(key, sharedEmbeddedURL+"|") {
				delete(sharedTemplates, key)
			}
		}
		sharedTemplatesMu.Unlock()
		sharedEmbedded = nil
		sharedEmbeddedURL = ""
	}

	return sharedEmbeddedURL, release, nil
}

func createSharedDatabase(ctx context.Context, adminURL string) (*TestDatabase, error) {
	templateName, err := sharedTemplateDatabase(ctx, adminURL)
	if err != nil {
		return nil, err
	}
	dbName, err := randomDBName()
	if err != nil {
		return nil, err
	}
	if err := execAdmin(
		ctx,
		adminURL,
		"CREATE DATABASE "+quoteIdent(dbName)+" TEMPLATE "+quoteIdent(templateName),
	); err != nil {
		return nil, fmt.Errorf("failed to create test database: %w", err)
	}
	connStr, err := databaseURL(adminURL, dbName)
	if err != nil {
		return nil, err
	}
	pool, queries, err := connectDatabase(ctx, connStr)
	if err != nil {
		return nil, err
	}
	return &TestDatabase{
		ConnectionString: connStr,
		Pool:             pool,
		Queries:          queries,
		adminURL:         adminURL,
		dbName:           dbName,
	}, nil
}

func sharedTemplateDatabase(ctx context.Context, adminURL string) (string, error) {
	stateKey, templateName, err := templateStateKey(adminURL)
	if err != nil {
		return "", err
	}

	sharedTemplatesMu.Lock()
	state := sharedTemplates[stateKey]
	if state == nil {
		state = &sharedTemplateState{}
		sharedTemplates[stateKey] = state
	}
	sharedTemplatesMu.Unlock()

	state.once.Do(func() {
		state.name = templateName
		state.err = ensureTemplateDatabase(ctx, adminURL, templateName)
	})
	if state.err != nil {
		return "", state.err
	}
	return state.name, nil
}

func templateStateKey(adminURL string) (string, string, error) {
	hash, err := templateHash()
	if err != nil {
		return "", "", err
	}
	templateName := "gecko_test_template_" + hash
	return adminURL + "|" + templateName, templateName, nil
}

func templateHash() (string, error) {
	h := sha256.New()
	if err := hashEmbeddedMigrations(h); err != nil {
		return "", err
	}
	testData, _, err := readTestData()
	if err != nil {
		return "", err
	}
	_, _ = h.Write([]byte("sql/tests/test-data.sql\x00"))
	_, _ = h.Write(testData)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:])[:16], nil
}

func hashEmbeddedMigrations(h hash.Hash) error {
	return fs.WalkDir(
		assets.EmbeddedAssets,
		"migrations",
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			b, err := assets.EmbeddedAssets.ReadFile(path)
			if err != nil {
				return err
			}
			_, _ = h.Write([]byte(path))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write(b)
			return nil
		},
	)
}

func ensureTemplateDatabase(ctx context.Context, adminURL, templateName string) error {
	return withAdminLock(ctx, adminURL, func(conn *sql.Conn) error {
		var exists bool
		if err := conn.QueryRowContext(
			ctx,
			"SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)",
			templateName,
		).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check test template database: %w", err)
		}
		if exists {
			return nil
		}

		if _, err := conn.ExecContext(ctx, "CREATE DATABASE "+quoteIdent(templateName)); err != nil {
			return fmt.Errorf("failed to create test template database: %w", err)
		}

		connStr, err := databaseURL(adminURL, templateName)
		if err != nil {
			return err
		}
		if err := prepareTemplateDatabase(ctx, connStr); err != nil {
			_, _ = conn.ExecContext(
				ctx,
				"DROP DATABASE IF EXISTS "+quoteIdent(templateName)+" WITH (FORCE)",
			)
			return err
		}
		return nil
	})
}

func prepareTemplateDatabase(ctx context.Context, connStr string) error {
	if err := runMigrations(connStr); err != nil {
		return err
	}
	if err := loadTestData(ctx, connStr); err != nil {
		return err
	}
	return nil
}

func connectDatabase(
	ctx context.Context,
	connStr string,
) (*pgxpool.Pool, *store.Queries, error) {
	if err := waitForDatabase(connStr); err != nil {
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

func withAdminLock(ctx context.Context, adminURL string, fn func(*sql.Conn) error) error {
	db, err := sql.Open("pgx", adminURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := waitForOpenDatabase(db); err != nil {
		return err
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock(hashtext('gecko_test_template'))"); err != nil {
		return fmt.Errorf("failed to lock test database template: %w", err)
	}
	defer func() {
		if _, err := conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(hashtext('gecko_test_template'))"); err != nil {
			slog.Error("failed to unlock test database template", "err", err)
		}
	}()

	return fn(conn)
}

func runMigrations(connStr string) error {
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database for migrations: %w", err)
	}
	defer db.Close()

	if err := waitForOpenDatabase(db); err != nil {
		return err
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

func waitForDatabase(connStr string) error {
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()
	return waitForOpenDatabase(db)
}

func waitForOpenDatabase(db *sql.DB) error {
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
	return nil
}

func loadTestData(ctx context.Context, connStr string) error {
	testData, foundPath, err := readTestData()
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

func readTestData() ([]byte, string, error) {
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
		return nil, "", err
	}
	return testData, foundPath, nil
}

func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// Close releases the pool, drops the per-test database, and releases the shared
// Postgres instance (embedded or external) once the last test using it finishes.
func (pc *TestDatabase) Close(ctx context.Context) {
	if pc.Pool != nil {
		pc.Pool.Close()
	}

	if pc.dbName != "" {
		if err := execAdmin(ctx, pc.adminURL, "DROP DATABASE IF EXISTS "+quoteIdent(pc.dbName)+" WITH (FORCE)"); err != nil {
			slog.Error("failed to drop test database", "db", pc.dbName, "err", err)
		}
		if pc.releaseShared != nil {
			pc.releaseShared()
		}
	}
}
