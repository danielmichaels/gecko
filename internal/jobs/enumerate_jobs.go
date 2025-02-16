package jobs

import (
	"context"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/scanner"
	"github.com/danielmichaels/doublestag/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
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
	DB     *pgxpool.Pool
	river.WorkerDefaults[EnumerateSubdomainArgs]
}

func (w *EnumerateSubdomainWorker) Work(ctx context.Context, job *river.Job[EnumerateSubdomainArgs]) error {
	dnsClient := scanner.NewDNSClient()
	tx, err := w.DB.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	rc := river.ClientFromContext[pgx.Tx](ctx)

	err = dnsClient.EnumerateWithSubfinderCallback(ctx, job.Args.Domain, job.Args.Concurrency, func(entry *resolve.HostEntry) {
		_, err := rc.InsertTx(ctx, tx, ResolveDomainArgs{
			Domain: entry.Host,
		}, nil)
		if err != nil {
			w.Logger.Error("failed to queue resolver job", "domain", entry.Host, "error", err)
		}
	})

	if err != nil {
		return fmt.Errorf("enumerate subdomains: %w", err)
	}

	return tx.Commit(ctx)
}

type ResolveDomainArgs struct {
	Domain string `json:"domain"`
}

func (ResolveDomainArgs) Kind() string { return "resolve_domain" }

type ResolveDomainWorker struct {
	Logger slog.Logger
	Store  *store.Queries
	river.WorkerDefaults[ResolveDomainArgs]
}

func (w *ResolveDomainWorker) Work(ctx context.Context, job *river.Job[ResolveDomainArgs]) error {
	dnsClient := scanner.NewDNSClient()

	result := scanner.SubdomainResult{
		Name: job.Args.Domain,
	}

	lookups := []struct {
		field  *[]string
		lookup func(string) ([]string, bool)
	}{
		{&result.A, dnsClient.LookupA},
		{&result.AAAA, dnsClient.LookupAAAA},
		{&result.CNAME, dnsClient.LookupCNAME},
		{&result.MX, dnsClient.LookupMX},
		{&result.TXT, dnsClient.LookupTXT},
		{&result.NS, dnsClient.LookupNS},
		{&result.PTR, dnsClient.LookupPTR},
		{&result.SRV, dnsClient.LookupSRV},
		{&result.CAA, dnsClient.LookupCAA},
		{&result.DNSKEY, dnsClient.LookupDNSKEY},
		{&result.SOA, dnsClient.LookupSOA},
	}

	for _, l := range lookups {
		if records, ok := l.lookup(job.Args.Domain + "."); ok && len(records) > 0 {
			*l.field = records
		}
	}

	// todo: Store results in database
	if err := scanner.RecordHandler(result); err != nil {
		w.Logger.Error("failed to handle domain resolution", "error", err)
		return fmt.Errorf("RecordHandler: %w", err)
	}

	return nil
}
