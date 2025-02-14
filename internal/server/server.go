package webserver

import (
	"context"
	"errors"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/config"
	"github.com/danielmichaels/doublestag/internal/store"
	"github.com/danielmichaels/doublestag/internal/version"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/httplog/v2"
)

type Application struct {
	Config *config.Conf
	Logger *slog.Logger
	Db     *store.Queries
}

func httpLogger(cfg *config.Conf) *httplog.Logger {
	var output io.Writer = os.Stdout
	logger := httplog.NewLogger("web", httplog.Options{
		JSON:             cfg.AppConf.LogJson,
		LogLevel:         cfg.AppConf.LogLevel,
		Concise:          cfg.AppConf.LogConcise,
		RequestHeaders:   true,
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

func (app *Application) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", app.Config.Server.APIPort),
		Handler:      app.routes(),
		IdleTimeout:  app.Config.Server.TimeoutIdle,
		ReadTimeout:  app.Config.Server.TimeoutRead,
		WriteTimeout: app.Config.Server.TimeoutWrite,
	}
	app.Logger.Info("HTTP server listening", "port", app.Config.Server.APIPort)
	wg := sync.WaitGroup{}
	shutdownError := make(chan error)
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		s := <-quit

		app.Logger.Warn("signal caught", "signal", s.String())

		// Allow processes to finish with a ten-second window
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx)
		if err != nil {
			shutdownError <- err
		}
		app.Logger.Warn("web-server", "addr", srv.Addr, "msg", "completing background tasks")
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
		app.Logger.Warn("web-server shutdown err", "addr", srv.Addr, "msg", "stopped server")
		return err
	}
	return nil
}
