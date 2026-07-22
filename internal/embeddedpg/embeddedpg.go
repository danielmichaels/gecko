package embeddedpg

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

// Options controls the embedded Postgres instance.
// Zero value is suitable for ephemeral test use: temp data dir, random free port,
// and the postgres/postgres credentials matching the test helpers.
type Options struct {
	// Logger routes embedded-postgres process output (initdb, pg_ctl) through slog at
	// Debug level. Nil = discard (keeps dev logs clean; the PG process is noisy).
	Logger   *slog.Logger
	User     string
	Password string
	Database string
	// DataDir is the directory for Postgres data files. Empty = temp dir (removed on Stop).
	DataDir string
	// Version is the Postgres version. Defaults to V18.
	Version embeddedpostgres.PostgresVersion
	// Port 0 means a random free port is chosen.
	Port uint32
}

// Server is a running embedded Postgres instance.
type Server struct {
	DSN     string
	pg      *embeddedpostgres.EmbeddedPostgres
	dataDir string
	// owned temp dirs cleaned up on Stop; empty strings = not owned
	ownedDataDir    string
	ownedRuntimeDir string
}

func (o *Options) applyDefaults() error {
	if o.User == "" {
		o.User = "postgres"
	}
	if o.Password == "" {
		o.Password = "postgres"
	}
	if o.Database == "" {
		o.Database = "test-db"
	}
	if o.Version == "" {
		o.Version = embeddedpostgres.V18
	}
	if o.Port == 0 {
		p, err := freePort()
		if err != nil {
			return fmt.Errorf("embeddedpg: find free port: %w", err)
		}
		o.Port = uint32(p)
	}
	return nil
}

// stableBinDir returns the shared, stable extraction dir. Setting BinariesPath to
// this path prevents concurrent Start() calls from deleting each other's extracted
// files (the default RuntimePath is also this dir and is rm-rf'd on every Start).
func stableBinDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("embeddedpg: home dir: %w", err)
	}
	return filepath.Join(home, ".embedded-postgres-go", "extracted"), nil
}

// portInUse returns true when something is already accepting connections on the given port.
func portInUse(port uint32) bool {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return true
	}
	l.Close()
	return false
}

// Start launches an embedded Postgres instance and returns once it is ready.
// If opts.DataDir is empty a temporary directory is created and removed on Stop.
// Each call uses its own RuntimePath so parallel instances do not race on extraction.
//
// For persistent dev use (DataDir set): if the port is already occupied — e.g. because
// a previous run was killed before Stop() — Start() returns a handle that points at the
// existing process without launching a new one. Stop() on such a handle is a no-op.
func Start(opts Options) (*Server, error) {
	if err := opts.applyDefaults(); err != nil {
		return nil, err
	}

	// Reuse a running instance for persistent data dirs (dev mode). When air or the OS
	// kills the process before graceful shutdown, PG keeps running on the same port.
	if opts.DataDir != "" && portInUse(opts.Port) {
		dsn := fmt.Sprintf(
			"postgres://%s:%s@localhost:%d/%s?sslmode=disable",
			opts.User, opts.Password, opts.Port, opts.Database,
		)
		return &Server{DSN: dsn}, nil
	}

	// Owned temp dirs (non-empty = we created them, we remove them on Stop).
	var ownedDataDir, ownedRuntimeDir string

	dataDir := opts.DataDir
	if dataDir == "" {
		tmp, err := os.MkdirTemp("", "embeddedpg-data-*")
		if err != nil {
			return nil, fmt.Errorf("embeddedpg: mkdirtemp data: %w", err)
		}
		dataDir = tmp
		ownedDataDir = tmp
	}

	// Each instance gets its own runtime dir so Start()'s os.RemoveAll(runtimePath)
	// does not delete the shared extracted binaries used by other parallel instances.
	runtimeDir, err := os.MkdirTemp("", "embeddedpg-rt-*")
	if err != nil {
		if ownedDataDir != "" {
			os.RemoveAll(ownedDataDir) //nolint:errcheck
		}
		return nil, fmt.Errorf("embeddedpg: mkdirtemp runtime: %w", err)
	}
	ownedRuntimeDir = runtimeDir

	binDir, err := stableBinDir()
	if err != nil {
		os.RemoveAll(ownedDataDir)    //nolint:errcheck
		os.RemoveAll(ownedRuntimeDir) //nolint:errcheck
		return nil, err
	}

	cfg := embeddedpostgres.DefaultConfig().
		Username(opts.User).
		Password(opts.Password).
		Database(opts.Database).
		Port(opts.Port).
		DataPath(dataDir).
		RuntimePath(runtimeDir).
		BinariesPath(binDir).
		Version(opts.Version).
		Logger(&pgSlogWriter{l: opts.Logger})

	pg := embeddedpostgres.NewDatabase(cfg)
	if err := pg.Start(); err != nil {
		os.RemoveAll(ownedDataDir)    //nolint:errcheck
		os.RemoveAll(ownedRuntimeDir) //nolint:errcheck
		return nil, fmt.Errorf("embeddedpg: start: %w", err)
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@localhost:%d/%s?sslmode=disable",
		opts.User, opts.Password, opts.Port, opts.Database,
	)
	return &Server{
		DSN:             dsn,
		pg:              pg,
		dataDir:         dataDir,
		ownedDataDir:    ownedDataDir,
		ownedRuntimeDir: ownedRuntimeDir,
	}, nil
}

// Stop shuts down the embedded Postgres instance and removes any temp directories
// that were created by Start. It is a no-op when called on a reused instance
// (pg == nil), which happens in dev mode when PG survived a previous crash.
//
// pg_ctl stop -w (smart mode, no configurable timeout in this library) is not
// fully reliable: it can report success — and embeddedpostgres.Stop() returns
// no error — while the postmaster process is still alive with zero client
// connections. So Stop reads the postmaster PID before asking the library to
// stop, and force-kills it afterward if it's still running.
func (s *Server) Stop() error {
	if s.pg != nil {
		pid, pidErr := readPostmasterPID(s.dataDir)

		stopErr := s.pg.Stop()

		if pidErr == nil {
			if killErr := ensureProcessTerminated(pid, 5*time.Second); killErr != nil {
				return fmt.Errorf("embeddedpg: stop: %w", killErr)
			}
		}

		if stopErr != nil && pidErr != nil {
			return fmt.Errorf("embeddedpg: stop: %w", stopErr)
		}
	}
	if s.ownedDataDir != "" {
		os.RemoveAll(s.ownedDataDir) //nolint:errcheck
	}
	if s.ownedRuntimeDir != "" {
		os.RemoveAll(s.ownedRuntimeDir) //nolint:errcheck
	}
	return nil
}

// readPostmasterPID reads the postmaster PID from <dataDir>/postmaster.pid,
// whose first line is the PID. It must be read before calling
// embeddedpostgres.Stop() — Postgres removes this file early in its shutdown
// sequence, often before all backend/worker processes have actually exited.
func readPostmasterPID(dataDir string) (int, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "postmaster.pid"))
	if err != nil {
		return 0, err
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	pid, err := strconv.Atoi(string(line))
	if err != nil {
		return 0, fmt.Errorf("parse postmaster.pid: %w", err)
	}
	return pid, nil
}

// ensureProcessTerminated polls pid for up to timeout, then SIGKILLs it if
// it's still alive — the backstop for pg_ctl stop reporting success while
// the process lives on.
func ensureProcessTerminated(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !processAlive(pid) {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return fmt.Errorf("pid %d survived pg_ctl stop and SIGKILL failed: %w", pid, err)
	}
	time.Sleep(200 * time.Millisecond)
	if processAlive(pid) {
		return fmt.Errorf("pid %d still alive after SIGKILL", pid)
	}
	return nil
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// pgSlogWriter routes embedded-postgres process output to slog at Debug level.
// When l is nil all output is discarded, keeping logs clean by default.
type pgSlogWriter struct{ l *slog.Logger }

func (w *pgSlogWriter) Write(p []byte) (int, error) {
	if w.l != nil {
		for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
			if line != "" {
				w.l.Debug(line)
			}
		}
	}
	return len(p), nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}
