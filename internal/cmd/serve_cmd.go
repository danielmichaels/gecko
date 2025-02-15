package cmd

import (
	"context"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/config"
	"github.com/danielmichaels/doublestag/internal/jobs/riverjobs"
	"github.com/danielmichaels/doublestag/internal/server"
	"github.com/danielmichaels/doublestag/internal/store"
)

const svcAPI = "serve"

type ServeCmd struct {
	WorkerCount   int  `short:"w" help:"Number of workers to start" default:"100"`
	DisableWorker bool `help:"Disable the worker" default:"false"`
}

func (s *ServeCmd) validateArgs() error {
	if s.WorkerCount < 1 {
		return fmt.Errorf("invalid number of workers specified - must be greater than 0")
	}
	if s.WorkerCount > 10000 {
		return fmt.Errorf("invalid number of workers specified - must be less than 10000")
	}
	return nil
}

func (s *ServeCmd) Run() error {
	if err := s.validateArgs(); err != nil {
		return err
	}
	cfg := config.AppConfig()
	logger, lctx := setupLogger(svcAPI, cfg)
	ctx, cancel := context.WithCancel(lctx)
	defer cancel()

	db, err := store.NewDatabasePool(ctx, cfg)
	if err != nil {
		logger.Error("database error", "error", err)
	}
	defer db.Close()
	err = db.Ping(ctx)
	if err != nil {
		logger.Error("database ping error", "error", err)
	}
	dbtx := store.New(db)

	rc, err := riverjobs.New(ctx, logger, db, dbtx, s.WorkerCount)
	if err != nil {
		logger.Error("worker error", "error", err)
	}

	app := server.New(cfg, logger, dbtx, rc)

	if !s.DisableWorker {
		if err := app.RC.Work(ctx); err != nil {
			app.Log.Error("river worker error", "error", err)
			return err
		}
	}

	err = app.Serve(ctx)
	if err != nil {
		app.Log.Error("api server error", "error", err, "msg", "failed to start server")
	}
	app.Log.Info("system shutdown")
	if err := app.RC.Close(ctx); err != nil {
		app.Log.Error("close error", "error", err)
		return err
	}

	return nil
}
