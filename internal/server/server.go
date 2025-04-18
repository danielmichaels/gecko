package server

import (
	"context"
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

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/version"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/go-chi/httplog/v2"
)

type Server struct {
	Conf    *config.Conf
	Log     *slog.Logger
	Db      *store.Queries
	PgxPool *pgxpool.Pool
	RC      *river.Client[pgx.Tx]
}

func New(
	c *config.Conf,
	l *slog.Logger,
	db *store.Queries,
	pgxPool *pgxpool.Pool,
	RC *river.Client[pgx.Tx],
) *Server {
	return &Server{Conf: c, Log: l, Db: db, RC: RC, PgxPool: pgxPool}
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
