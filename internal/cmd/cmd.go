package cmd

import (
	"context"
	"fmt"
	"github.com/danielgtaylor/huma/v2"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/logging"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

type Globals struct {
	ServerURL  string          `help:"Server URL"`
	Username   string          `help:"Username for authentication"`
	Password   string          `help:"Password for authentication"`
	ConfigFile kong.ConfigFlag `short:"c" help:"Location of client config files" type:"yamlfile" default:"${config_path}"`
	Format     string          `help:"Output format" short:"f" default:"text" enum:"text,json"`
}

func ValidateStartup(g *Globals) error {
	if g.ServerURL == "" {
		return fmt.Errorf(
			"server-url is required - set via config, GECKO_SERVER_URL or --server-url flag",
		)
	}
	if g.Username == "" {
		return fmt.Errorf(
			"username is required - set via config, GECKO_USERNAME or --username flag",
		)
	}
	if g.Password == "" {
		return fmt.Errorf(
			"password is required - set via config, GECKO_PASSWORD or --password flag",
		)
	}
	return nil
}

type Setup struct {
	Config  *config.Conf
	Logger  *slog.Logger
	PgxPool *pgxpool.Pool
	Store   *store.Queries
	Ctx     context.Context
	Cancel  context.CancelFunc
	RC      *river.Client[pgx.Tx]
}
type SetupOption func(*Setup)

// WithRiver sets up a River client.
//
// workerCount is the number of workers to start.
//
// addWorkers is whether to add workers to the River client. Used in server to disable workers.
func WithRiver(workerCount int, addWorkers bool) SetupOption {
	return func(s *Setup) {
		riverCfg := jobs.Config{
			PgxPool:     s.PgxPool,
			Logger:      s.Logger,
			Store:       s.Store,
			WorkerCount: workerCount,
			AddWorkers:  addWorkers,
		}

		rc, err := jobs.New(s.Ctx, riverCfg)
		if err != nil {
			// fixme: handle error
			panic("failed to create River client: " + err.Error())
		}
		s.RC = rc
	}
}

// WithSilentLogging is the default mode for CLI commands. It discards
// logs. CLI then relies upon printing. Using Verbose turns this off and
// logs will be output on CLI invocation.
func WithSilentLogging() SetupOption {
	return func(s *Setup) {
		handler := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{})
		s.Logger = slog.New(handler)
	}
}

func NewSetup(service string, opts ...SetupOption) (*Setup, error) {
	cfg := config.AppConfig()
	logger, lctx := logging.SetupLogger(service, cfg)
	ctx, cancel := context.WithCancel(lctx)

	db, err := store.NewDatabasePool(ctx, cfg)
	if err != nil {
		logger.Error("database error", "error", err)
		cancel()
		return nil, err
	}

	if err := db.Ping(ctx); err != nil {
		logger.Error("database ping error", "error", err)
		db.Close()
		cancel()
		return nil, err
	}
	s := &Setup{
		Config:  cfg,
		Logger:  logger,
		PgxPool: db,
		Store:   store.New(db),
		Ctx:     ctx,
		Cancel:  cancel,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func (s *Setup) Close() {
	s.Logger.Info("shutting down PgxPool and River")
	if s.RC != nil {
		if err := s.RC.Stop(s.Ctx); err != nil { // Use Stop instead of Close
			s.Logger.Error("failed to stop River client", "error", err)
		}
	}
	s.Cancel()
	s.PgxPool.Close()
	s.Logger.Info("shutdown complete")
}

// createCancellableContext creates a new context.Context that is cancelled when an interrupt signal is received.
// The returned context and cancel function can be used to control the lifetime of long-running operations.
func createCancellableContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	return ctx, cancel
}

// handleHumaError provides consistent error messages for CLI commands.
//
// Huma conforms to RFC 9457 Problem Details for HTTP APIs. We continue this
// consistency and parse the errors into human-readable messages.
//
// ref: https://huma.rocks/features/response-errors/?h=errors#error-model
func handleHumaError(apiErr huma.ErrorModel) error {
	msg := fmt.Sprintf("%s: %s\n", apiErr.Title, apiErr.Detail)

	if len(apiErr.Errors) > 0 {
		msg += "Validation errors:\n"
		for _, e := range apiErr.Errors {
			msg += fmt.Sprintf("- %s at %s (value: %v)\n",
				e.Message, e.Location, e.Value)
		}
	}
	return fmt.Errorf(msg)
}

// HandleRequestError provides consistent error messages for CLI commands
func HandleRequestError(err error, serverURL string) error {
	switch {
	case strings.Contains(err.Error(), "connection refused"):
		return fmt.Errorf("server is not running at %s", serverURL)
	case strings.Contains(err.Error(), "no such host"):
		return fmt.Errorf("could not resolve host %s", serverURL)
	case strings.Contains(err.Error(), "timeout"):
		return fmt.Errorf("connection timed out to %s", serverURL)
	case strings.Contains(err.Error(), "404"):
		return fmt.Errorf("resource not found at %s", serverURL)
	case strings.Contains(err.Error(), "401"):
		return fmt.Errorf("authentication failed - please check your credentials")
	case strings.Contains(err.Error(), "403"):
		return fmt.Errorf("you don't have permission to access this resource")
	case strings.Contains(err.Error(), "404"):
		return fmt.Errorf("resource not found")
	case strings.Contains(err.Error(), "422"):
		return fmt.Errorf("unprocessable entity - invalid data submitted")
	default:
		return fmt.Errorf("connection error: %v", err)
	}
}
