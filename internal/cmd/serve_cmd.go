package cmd

import (
	"fmt"

	"github.com/danielmichaels/gecko/internal/server"
	"github.com/danielmichaels/gecko/internal/store"
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

	setup, err := NewSetup(svcAPI, WithRiver(s.WorkerCount, !s.DisableWorker))
	if err != nil {
		return err
	}
	defer setup.Close()

	dbtx := store.New(setup.PgxPool)
	app := server.New(setup.Config, setup.Logger, dbtx, setup.PgxPool, setup.RC)

	if !s.DisableWorker {
		if err := app.RC.Start(setup.Ctx); err != nil {
			app.Log.Error("river worker error", "error", err)
			return err
		}
	}

	err = app.Serve(setup.Ctx)
	if err != nil {
		app.Log.Error("api server error", "error", err, "msg", "failed to start server")
	}
	app.Log.Info("system shutdown")
	return nil
}
