package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/ui"
	"github.com/danielmichaels/gecko/internal/version"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/go-chi/httplog/v2"
)

type Server struct {
	Conf         *config.Conf
	Log          *slog.Logger
	Db           *store.Queries
	PgxPool      *pgxpool.Pool
	RC           *river.Client[pgx.Tx]
	AuthProvider auth.Provider
	Svc          *service.Service
	UI           *ui.App
	UIHandlers   *ui.Handlers
}

func New(
	c *config.Conf,
	l *slog.Logger,
	db *store.Queries,
	pgxPool *pgxpool.Pool,
	RC *river.Client[pgx.Tx],
) (*Server, error) {
	provider, err := auth.NewProvider(auth.Config{
		Provider:   c.Auth.Provider,
		BcryptCost: c.Auth.BcryptCost,
	}, db)
	if err != nil {
		return nil, fmt.Errorf("auth provider: %w", err)
	}

	svc := service.New(c, l, db, pgxPool, RC, provider)

	csrfKey, err := resolveCSRFKey(c.Auth.CSRFSecret, l)
	if err != nil {
		return nil, fmt.Errorf("csrf key: %w", err)
	}
	cookieCfg := ui.CookieConfig{
		Name:     c.Auth.SessionCookieName,
		Secure:   c.Auth.SessionCookieSecure,
		SameSite: parseSameSite(c.Auth.SessionCookieSameSite),
	}

	uiApp := ui.New(svc.AuthService(), cookieCfg, csrfKey, l)
	return &Server{
		Conf:         c,
		Log:          l,
		Db:           db,
		RC:           RC,
		PgxPool:      pgxPool,
		AuthProvider: provider,
		Svc:          svc,
		UI:           uiApp,
		UIHandlers:   ui.NewHandlers(svc, uiApp, cookieCfg, l),
	}, nil
}

// resolveCSRFKey returns the configured key or a freshly generated random one.
// A random key means CSRF tokens do not survive a server restart, which is safe
// but inconvenient for rolling deployments — callers should set AUTH_CSRF_SECRET.
func resolveCSRFKey(secret string, l *slog.Logger) ([]byte, error) {
	if secret != "" {
		return []byte(secret), nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	l.Warn(
		"CSRF key is ephemeral — tokens will not survive a restart; set AUTH_CSRF_SECRET in production",
	)
	return key, nil
}

// parseSameSite converts the string env-var value to http.SameSite.
func parseSameSite(s string) http.SameSite {
	switch s {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func httpLogger(cfg *config.Conf) *httplog.Logger {
	var output io.Writer = os.Stdout
	logger := httplog.NewLogger("web", httplog.Options{
		JSON:             cfg.AppConf.LogJson,
		LogLevel:         cfg.AppConf.LogLevel,
		Concise:          cfg.AppConf.LogConcise,
		RequestHeaders:   cfg.AppConf.LogRequestHeaders,
		ResponseHeaders:  cfg.AppConf.LogResponseHeaders,
		MessageFieldName: "message",
		TimeFieldFormat:  time.RFC3339,
		Tags: map[string]string{
			"version": version.Get(),
		},
		QuietDownRoutes: []string{
			"/",
			"/ping",
			"/healthz",
			"/static/app.css",
			"/static/datastar.js",
		},
		QuietDownPeriod: 10 * time.Second,
		Writer:          output,
	})
	return logger
}

func (app *Server) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", app.Conf.Server.APIPort),
		Handler:      app.routes(),
		IdleTimeout:  app.Conf.Server.TimeoutIdle,
		ReadTimeout:  app.Conf.Server.TimeoutRead,
		WriteTimeout: app.Conf.Server.TimeoutWrite,
	}
	app.Log.Info("HTTP server listening", "port", app.Conf.Server.APIPort)
	wg := sync.WaitGroup{}
	shutdownError := make(chan error)
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		s := <-quit

		app.Log.Warn("signal caught", "signal", s.String())

		// Allow processes to finish with a ten-second window
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx)
		if err != nil {
			shutdownError <- err
		}
		app.Log.Warn("web-server", "addr", srv.Addr, "msg", "completing background tasks")
		// Call wait so that the wait group can decrement to zero.
		wg.Wait()
		shutdownError <- nil
	}()

	err := srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	err = <-shutdownError
	if err != nil {
		app.Log.Warn("web-server shutdown err", "addr", srv.Addr, "msg", "stopped server")
		return err
	}
	return nil
}
