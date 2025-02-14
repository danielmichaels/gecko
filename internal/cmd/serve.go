package cmd

import (
	"context"
	"github.com/danielmichaels/doublestag/internal/config"
	webserver "github.com/danielmichaels/doublestag/internal/server"
	"github.com/danielmichaels/doublestag/internal/store"
)

const svcAPI = "serve"

type ServeCmd struct{}

func (s *ServeCmd) Run(g *Globals) error {
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
	app := &webserver.Application{
		Config: cfg,
		Logger: logger,
		Db:     dbtx,
	}

	err = app.Serve(ctx)
	if err != nil {
		app.Logger.Error("api server error", "error", err, "msg", "failed to start server")
	}
	app.Logger.Info("system shutdown")

	return nil
}
