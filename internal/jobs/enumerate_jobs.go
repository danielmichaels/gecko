package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/tracing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/danielmichaels/gecko/internal/observer"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/riverqueue/river"
)

type EnumerateSubdomainArgs struct {
	DomainJobArgs
	Concurrency int `json:"concurrency"`
}

func (EnumerateSubdomainArgs) Kind() string { return "enumerate_subdomain" }

func (EnumerateSubdomainArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueEnumeration,
	}
}

type EnumerateSubdomainWorker struct {
	river.WorkerDefaults[EnumerateSubdomainArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *EnumerateSubdomainWorker) Timeout(*river.Job[EnumerateSubdomainArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *EnumerateSubdomainWorker) Work(
	ctx context.Context,
	job *river.Job[EnumerateSubdomainArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	dnsClient := w.Resolver
	rc := river.ClientFromContext[pgx.Tx](ctx)

	// Drain the discovered host list WITHOUT holding a transaction across the
	// network sweep. Holding a tx (and its row locks) open for the whole
	// multi-minute subfinder run would deadlock against the per-host inserts.
	seen := make(map[string]struct{})
	var hosts []string
	err := dnsClient.EnumerateWithSubfinderCallback(
		ctx,
		job.Args.DomainName,
		job.Args.Concurrency,
		func(entry *resolve.HostEntry) {
			name := dnsrecords.CanonicalizeDomain(entry.Host)
			if name == "" {
				return
			}
			if _, ok := seen[name]; ok {
				return
			}
			seen[name] = struct{}{}
			hosts = append(hosts, name)
		},
	)
	if err != nil {
		return fmt.Errorf("enumerate subdomains: %w", err)
	}

	// Process each host in its own short transaction so one bad host can't roll
	// back the whole sweep and the advisory-lock scope stays bounded.
	window := config.AppConfig().AppConf.ScanRecencyWindow
	for _, host := range hosts {
		w.Logger.InfoContext(ctx, "enumerate_subdomain", "host", host)
		if err := w.processDiscoveredHost(ctx, rc, job.Args.DomainJobArgs, host, window); err != nil {
			w.Logger.ErrorContext(
				ctx,
				"failed to process discovered host",
				"host", host,
				"error", err,
			)
		}
	}
	return nil
}

// processDiscoveredHost creates (or reuses) the discovered domain and enqueues a
// scan for it in a single short transaction. Recursion is bounded: discovered
// scans do NOT themselves enumerate (EnumerateSubdomains: false), so wildcard
// DNS can't drive an unbounded re-subfinding loop. The advisory lock + recency
// guard inside EnqueueDomainScan dedupe concurrent discoveries of the same host.
func (w *EnumerateSubdomainWorker) processDiscoveredHost(
	ctx context.Context,
	rc *river.Client[pgx.Tx],
	parent DomainJobArgs,
	host string,
	window time.Duration,
) (err error) {
	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin per-host transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && rbErr != pgx.ErrTxClosed {
				w.Logger.ErrorContext(ctx, "per-host transaction rollback", "error", rbErr)
			}
		}
	}()
	st := w.Store.WithTx(tx)

	d, err := st.DomainsCreate(ctx, store.DomainsCreateParams{
		TenantID:   pgtype.Int4{Int32: parent.TenantID, Valid: true},
		Name:       host,
		DomainType: store.DomainTypeSubdomain,
		Source:     store.DomainSourceDiscovered,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		return fmt.Errorf("create discovered domain: %w", err)
	}

	parentScanID := parent.ScanID
	_, err = EnqueueDomainScan(ctx, rc, tx, st, DomainScanTarget{
		TenantID:   parent.TenantID,
		DomainID:   d.ID,
		DomainUID:  d.Uid,
		DomainName: d.Name,
		Status:     d.Status,
	}, DomainScanOptions{
		EnumerateSubdomains: false, // bounded: discovered hosts don't re-enumerate
		ParentScanID:        &parentScanID,
		Source:              store.ScanSourceDiscovered,
		Force:               false, // discovered scans are subject to the recency guard
		RecencyWindow:       window,
	})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type ResolveDomainArgs struct {
	DomainJobArgs
}

func (ResolveDomainArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueResolver,
	}
}
func (ResolveDomainArgs) Kind() string { return "resolve_domain" }

type ResolveDomainWorker struct {
	river.WorkerDefaults[ResolveDomainArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

// recordResolved syncs every resolved DNS record type for one scan through the
// observation recorder inside a single transaction, so the whole scan's
// projection changes and observations commit or roll back together.
func (w *ResolveDomainWorker) recordResolved(
	ctx context.Context,
	ident DomainJobArgs,
	resolved observer.Resolved,
) (err error) {
	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin recorder transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && rbErr != pgx.ErrTxClosed {
				w.Logger.ErrorContext(ctx, "recorder rollback", "error", rbErr)
			}
		}
	}()
	rec := observer.New(w.Store.WithTx(tx))
	if err = rec.RecordAll(ctx, observer.DomainIdentity{
		TenantID:   ident.TenantID,
		DomainID:   ident.DomainID,
		DomainUID:  ident.DomainUID,
		DomainName: ident.DomainName,
		ScanID:     ident.ScanID,
	}, resolved); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Work resolves every DNS record type for the threaded domain with a three-way
// resolution status and syncs them through the observation recorder: the live
// projection is kept current, the change log is appended, and deletions are
// applied only on an authoritative result. The domain identity arrives on the
// job args, so the worker never rediscovers or creates the domain.
func (w *ResolveDomainWorker) Work(ctx context.Context, job *river.Job[ResolveDomainArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	dnsClient := w.Resolver
	fqdn := job.Args.DomainName + "."

	lookup := func(qtype uint16) observer.TypeResult {
		entries, status := dnsClient.LookupWithStatus(fqdn, qtype)
		return observer.TypeResult{Entries: entries, Authoritative: status.Authoritative()}
	}
	resolved := observer.Resolved{
		A:      lookup(dns.TypeA),
		AAAA:   lookup(dns.TypeAAAA),
		CNAME:  lookup(dns.TypeCNAME),
		MX:     lookup(dns.TypeMX),
		TXT:    lookup(dns.TypeTXT),
		NS:     lookup(dns.TypeNS),
		SOA:    lookup(dns.TypeSOA),
		PTR:    lookup(dns.TypePTR),
		CAA:    lookup(dns.TypeCAA),
		SRV:    lookup(dns.TypeSRV),
		DNSKEY: lookup(dns.TypeDNSKEY),
		DS:     lookup(dns.TypeDS),
		RRSIG:  lookup(dns.TypeRRSIG),
	}

	if err := w.recordResolved(ctx, job.Args.DomainJobArgs, resolved); err != nil {
		return err
	}

	// CAA assessment runs unconditionally: a missing CAA record set is itself a
	// finding, so it must be enqueued even when no CAA records were resolved.
	if err := enqueueAssessment(ctx, w.PgxPool, &w.Logger, job.Args.DomainUID,
		AssessCAAArgs{DomainJobArgs: job.Args.DomainJobArgs}); err != nil {
		w.Logger.WarnContext(ctx, "failed to queue caa assessment",
			"domain", job.Args.DomainUID, "error", err)
	}

	// Minimum record set assessment runs unconditionally; missing essential
	// records are findings, and the assessor itself gates on apex domains.
	if err := enqueueAssessment(ctx, w.PgxPool, &w.Logger, job.Args.DomainUID,
		AssessMinimumRecordSetArgs{DomainJobArgs: job.Args.DomainJobArgs}); err != nil {
		w.Logger.WarnContext(ctx, "failed to queue minimum record set assessment",
			"domain", job.Args.DomainUID, "error", err)
	}

	// Nameserver config assessment runs unconditionally: a single nameserver (or
	// none) is itself a redundancy finding, so it must run regardless of the NS set.
	if err := enqueueAssessment(ctx, w.PgxPool, &w.Logger, job.Args.DomainUID,
		AssessNameserverConfigArgs{DomainJobArgs: job.Args.DomainJobArgs}); err != nil {
		w.Logger.WarnContext(ctx, "failed to queue nameserver config assessment",
			"domain", job.Args.DomainUID, "error", err)
	}

	// Nameserver health assessment probes each authoritative NS directly; an
	// unreachable nameserver is itself a finding, so it runs unconditionally.
	if err := enqueueAssessment(ctx, w.PgxPool, &w.Logger, job.Args.DomainUID,
		AssessNameserverHealthArgs{DomainJobArgs: job.Args.DomainJobArgs}); err != nil {
		w.Logger.WarnContext(ctx, "failed to queue nameserver health assessment",
			"domain", job.Args.DomainUID, "error", err)
	}

	// Email security assessment is data-dependent: enqueue only when TXT records
	// were discovered (SPF/DKIM/DMARC live in TXT).
	if len(resolved.TXT.Entries) > 0 {
		tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return err
		}
		defer func(tx pgx.Tx, ctx context.Context) {
			err := tx.Rollback(ctx)
			if err != nil && err != pgx.ErrTxClosed {
				w.Logger.ErrorContext(ctx, "failed to rollback tx", "err", err)
			}
		}(tx, ctx)
		rc := river.ClientFromContext[pgx.Tx](ctx)
		_, err = rc.InsertTx(
			ctx,
			tx,
			AssessEmailSecurityArgs{DomainJobArgs: job.Args.DomainJobArgs},
			nil,
		)
		if err != nil {
			w.Logger.WarnContext(ctx, "failed to queue email security assessment",
				"domain", job.Args.DomainUID, "error", err)
		}
		return tx.Commit(ctx)
	}

	return nil
}
