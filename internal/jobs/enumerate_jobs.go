package jobs

import (
	"context"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/scanner"
	"github.com/danielmichaels/doublestag/internal/store"
	"github.com/riverqueue/river"
	"log/slog"
)

type EnumerateSubdomainArgs struct {
	Domain      string `json:"domain"`
	Concurrency int    `json:"concurrency"`
}

func (EnumerateSubdomainArgs) Kind() string { return "enumerate_subdomain" }

type EnumerateSubdomainWorker struct {
	Logger slog.Logger
	DB     *store.Queries
	river.WorkerDefaults[EnumerateSubdomainArgs]
}

func (w *EnumerateSubdomainWorker) Work(ctx context.Context, job *river.Job[EnumerateSubdomainArgs]) error {
	dnsClient := scanner.NewDNSClient()
	output, err := dnsClient.EnumerateWithSubfinder(ctx, job.Args.Domain, job.Args.Concurrency)
	if err != nil {
		return fmt.Errorf("EnumerateWithSubfinder: %w", err)
	}

	if err := scanner.ProcessSubdomainResults(output, func(r scanner.SubdomainResult) error {
		if err := scanner.RecordHandler(r); err != nil {
			w.Logger.Error("failed to handle subdomain result", "error", err)
			return fmt.Errorf("RecordHandler: %w", err)
		}
		return nil
	}); err != nil {
		w.Logger.Error("ProcessSubdomainResults", "error", err)
		return fmt.Errorf("ProcessSubdomainResults: %w", err)
	}
	return nil
}
