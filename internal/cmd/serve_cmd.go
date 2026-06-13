package cmd

import (
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/config"
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
	// The server builds absolute links in outbound email (password reset, welcome)
	// from APP_PUBLIC_URL, so refuse to start without the config preconditions met.
	if err := config.AppConfig().Validate(); err != nil {
		return err
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

	if email, pass := setup.Config.Bootstrap.Email, setup.Config.Bootstrap.Password; email != "" &&
		pass != "" {
		_, created, berr := bootstrapOwner(
			setup.Ctx,
			setup.PgxPool,
			dbtx,
			setup.Config.Auth.BcryptCost,
			bootstrapParams{
				Email:      email,
				Password:   pass,
				TenantName: setup.Config.Bootstrap.TenantName,
			},
			false,
		)
		if berr != nil {
			return fmt.Errorf("auto-bootstrap owner: %w", berr)
		}
		if created {
			setup.Logger.Info(
				"auto-bootstrap: provisioned owner",
				"email",
				strings.ToLower(strings.TrimSpace(email)),
			)
		} else {
			setup.Logger.Info("auto-bootstrap: owner already present; skipped")
		}
	}

	app, err := server.New(setup.Config, setup.Logger, dbtx, setup.PgxPool, setup.RC)
	if err != nil {
		return err
	}

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
