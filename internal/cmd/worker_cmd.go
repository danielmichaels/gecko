package cmd

import (
	"fmt"
	"github.com/danielmichaels/doublestag/internal/jobs"
	"github.com/jackc/pgx/v5"
	"os"
	"os/signal"
	"syscall"
)

const svcWorkers = "worker"

type WorkerCmd struct{}

func (w *WorkerCmd) Run() error {
	setup, err := NewSetup(svcWorkers, WithRiver(100, true))
	if err != nil {
		return err
	}
	defer setup.Close()

	// create example insert
	// we use transactions to ensure the insert is atomic
	tx, err := setup.DB.BeginTx(setup.Ctx, pgx.TxOptions{})
	if err != nil {
		setup.Logger.Error("failed to start transaction", "error", err)
		return err
	}
	defer tx.Rollback(setup.Ctx)
	for i := range [10]int{} {
		_, err = setup.RC.InsertTx(setup.Ctx, tx, jobs.SendEmailArgs{
			To:      "foo@bar.com",
			From:    "Megaman",
			Subject: "I never lose " + fmt.Sprintf("%d", i),
			Body:    "Howdy",
		}, nil)
		if err != nil {
			setup.Logger.Error("failed to insert job", "error", err)
			return err
		}
	}

	_, err = setup.RC.InsertTx(setup.Ctx, tx, jobs.SendEmailArgs{
		To:      "foo@bar.com",
		From:    "Megaman",
		Subject: "I never lose",
		Body:    "Howdy",
	}, nil)
	tx.Commit(setup.Ctx)

	setup.Logger.InfoContext(setup.Ctx, "started worker")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	setup.Logger.Info("shutting down worker")
	return nil
}
