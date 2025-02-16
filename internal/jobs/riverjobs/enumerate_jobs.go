package riverjobs

import (
	"context"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/scanner"
	"github.com/riverqueue/river"
)

type EnumerateSubdomainArgs struct {
	Domain      string `json:"domain"`
	Concurrency int    `json:"concurrency"`
}

func (EnumerateSubdomainArgs) Kind() string { return "enumerate_subdomain" }

type EnumerateSubdomainWorker struct {
	river.WorkerDefaults[EnumerateSubdomainArgs]
}

func (w *EnumerateSubdomainWorker) Work(ctx context.Context, job *river.Job[EnumerateSubdomainArgs]) error {
	dnsClient := scanner.NewDNSClient()
	output, err := dnsClient.EnumerateWithSubfinder(context.Background(), job.Args.Domain, job.Args.Concurrency)
	if err != nil {
		return fmt.Errorf("EnumerateWithSubfinder: %w", err)
	}

	if err := scanner.ProcessSubdomainResults(output, func(r scanner.SubdomainResult) error {
		if err := scanner.RecordHandler(r); err != nil {
			return fmt.Errorf("RecordHandler: %w", err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("ProcessSubdomainResults: %w", err)
	}
	return nil
}
