package cmd

import (
	"context"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/config"
	"github.com/danielmichaels/doublestag/internal/jobs/riverjobs"
	"github.com/danielmichaels/doublestag/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"os"
	"os/signal"
	"syscall"
)

const svcWorkers = "worker"

type WorkerCmd struct{}

func (w *WorkerCmd) Run() error {
	cfg := config.AppConfig()
	logger, lctx := setupLogger(svcWorkers, cfg)
	ctx, cancel := context.WithCancel(lctx)
	defer cancel()

	db, err := store.NewDatabasePool(ctx, cfg)
	if err != nil {
		logger.Error("database error", "error", err)
		return err
	}
	defer db.Close()
	err = db.Ping(ctx)
	if err != nil {
		logger.Error("database ping error", "error", err)
		return err
	}
	dbtx := store.New(db)

	// setup example riverqueue
	rw := river.NewWorkers()
	river.AddWorker(rw, &riverjobs.SendEmailWorker{
		Logger: *logger,
		DB:     dbtx,
	})
	rc, err := river.NewClient(riverpgxv5.New(db), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 100},
		},
		Workers: rw,
	})
	if err != nil {
		logger.Error("failed to create worker", "error", err)
		return err
	}
	if err := rc.Start(ctx); err != nil {
		logger.Error("failed to start riverqueue worker", "error", err)
		return err
	}

	// create example insert
	// we use transactions to ensure the insert is atomic
	tx, err := db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		logger.Error("failed to start transaction", "error", err)
		return err
	}
	defer tx.Rollback(ctx)
	for i := range [10]int{} {
		_, err = rc.InsertTx(ctx, tx, riverjobs.SendEmailArgs{
			To:      "foo@bar.com",
			From:    "Megaman",
			Subject: "I never lose " + fmt.Sprintf("%d", i),
			Body:    "Howdy",
		}, nil)
		if err != nil {
			logger.Error("failed to insert job", "error", err)
			return err
		}
	}

	_, err = rc.InsertTx(ctx, tx, riverjobs.SendEmailArgs{
		To:      "foo@bar.com",
		From:    "Megaman",
		Subject: "I never lose",
		Body:    "Howdy",
	}, nil)
	tx.Commit(ctx)

	logger.InfoContext(ctx, "started worker")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	if err := rc.Stop(ctx); err != nil {
		logger.Error("failed to stop riverqueue worker", "error", err)
		return err
	}
	logger.Info("shutting down")
	return nil
}
