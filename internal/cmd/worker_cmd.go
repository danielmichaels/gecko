package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const svcWorkers = "worker"

type WorkerCmd struct {
	WorkerCount int `short:"w" help:"Number of workers to start" default:"100"`
}

func (w *WorkerCmd) validateArgs() error {
	if w.WorkerCount < 1 {
		return fmt.Errorf("invalid number of workers specified - must be greater than 0")
	}
	if w.WorkerCount > 10000 {
		return fmt.Errorf("invalid number of workers specified - must be less than 10000")
	}
	return nil
}

func (w *WorkerCmd) Run() error {
	if err := w.validateArgs(); err != nil {
		return err
	}

	setup, err := NewSetup(svcWorkers, WithRiver(w.WorkerCount, true))
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
