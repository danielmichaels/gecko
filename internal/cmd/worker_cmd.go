package cmd

import (
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

	if err := setup.RC.Start(setup.Ctx); err != nil {
		setup.Logger.Error("river worker error", "error", err)
		return err
	}
	setup.Logger.InfoContext(setup.Ctx, "started worker")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	setup.Logger.Info("shutting down worker")
	return nil
}
