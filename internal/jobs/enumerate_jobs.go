package jobs

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/dnsrecords"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/riverqueue/river"
)

type EnumerateSubdomainArgs struct {
	Domain      string `json:"domain"`
	Concurrency int    `json:"concurrency"`
}

func (EnumerateSubdomainArgs) Kind() string { return "enumerate_subdomain" }

func (EnumerateSubdomainArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueEnumeration,
	}
}

type EnumerateSubdomainWorker struct {
	river.WorkerDefaults[EnumerateSubdomainArgs]
	Logger  slog.Logger
	PgxPool *pgxpool.Pool
}

func (w *EnumerateSubdomainWorker) Work(
	ctx context.Context,
	job *river.Job[EnumerateSubdomainArgs],
) error {
	dnsClient := dnsclient.NewDNSClient()
	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func(tx pgx.Tx, ctx context.Context) {
		err := tx.Rollback(ctx)
		if err != nil {
			w.Logger.Error("transaction rollback", "error", err)
		}
	}(tx, ctx)

	rc := river.ClientFromContext[pgx.Tx](ctx)

	err = dnsClient.EnumerateWithSubfinderCallback(
		ctx,
		job.Args.Domain,
		job.Args.Concurrency,
		func(entry *resolve.HostEntry) {
			_, err := rc.InsertTx(ctx, tx, ResolveDomainArgs{
				Domain: entry.Host,
			}, nil)
			if err != nil {
				w.Logger.Error("failed to queue resolver job", "domain", entry.Host, "error", err)
			}
		},
	)
	if err != nil {
		return fmt.Errorf("enumerate subdomains: %w", err)
	}

	return tx.Commit(ctx)
}

type ResolveDomainArgs struct {
	Domain string `json:"domain"`
}

func (ResolveDomainArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueResolver,
	}
}
func (ResolveDomainArgs) Kind() string { return "resolve_domain" }

type ResolveDomainWorker struct {
	river.WorkerDefaults[ResolveDomainArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *ResolveDomainWorker) Work(ctx context.Context, job *river.Job[ResolveDomainArgs]) error {
	dnsClient := dnsclient.NewDNSClient()

	result := dnsclient.SubdomainResult{
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

	records := []struct {
		parser  func(string, string) (interface{}, error)
		name    string
		entries []string
	}{
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseA(d, r) },
			"A",
			result.A,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseAAAA(d, r) },
			"AAAA",
			result.AAAA,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseCNAME(d, r) },
			"CNAME",
			result.CNAME,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseTXT(d, r) },
			"TXT",
			result.TXT,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseNS(d, r) },
			"NS",
			result.NS,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseMX(d, r) },
			"MX",
			result.MX,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseSOARecord(d, r) },
			"SOA",
			result.SOA,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParsePTR(d, r) },
			"PTR",
			result.PTR,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseCAA(d, r) },
			"CAA",
			result.CAA,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseDNSKEY(d, r) },
			"DNSKEY",
			result.DNSKEY,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseDS(d, r) },
			"DS",
			result.DS,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseRRSIG(d, r) },
			"RRSIG",
			result.RRSIG,
		},
		{
			func(d, r string) (interface{}, error) { return dnsrecords.ParseSRV(d, r) },
			"SRV",
			result.SRV,
		},
	}

	for _, r := range records {
		for _, entry := range r.entries {
			parsed, err := r.parser(result.Name, entry)
			if err != nil {
				w.Logger.Error("failed to parse record",
					"type", r.name,
					"domain", result.Name,
					"error", err)
				continue
			}
			w.Logger.Info("parsed record", "parsed", parsed, "type", r.name)
			// Store parsed record using worker's services
			if r.name == "A" {
				// todo: example only - remove later
				d, err := w.Store.DomainsCreate(ctx, store.DomainsCreateParams{
					TenantID:   pgtype.Int4{Int32: 1, Valid: true},
					Name:       result.Name,
					DomainType: store.DomainTypeSubdomain,
					Source:     store.DomainSourceUserSupplied,
					Status:     store.DomainStatusActive,
				})
				if err != nil {
					return err
				}
				a, err := w.Store.RecordsCreateA(ctx, store.RecordsCreateAParams{
					DomainID:    pgtype.Int4{Int32: d.ID, Valid: true},
					Ipv4Address: entry,
				})
				if err != nil {
					return err
				}
				w.Logger.Debug(
					"found A record",
					"ip",
					a.Ipv4Address,
					"uid",
					a.Uid,
					"domain",
					d.Name,
				)
			}
		}
	}

	return nil
}
