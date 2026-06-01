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

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *EnumerateSubdomainWorker) Timeout(*river.Job[EnumerateSubdomainArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *EnumerateSubdomainWorker) Work(
	ctx context.Context,
	job *river.Job[EnumerateSubdomainArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	dnsClient := dnsclient.New()
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
		Source:              store.DomainSourceDiscovered,
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
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

// Work resolves the threaded domain's records and persists them to the live
// projection tables. The domain identity (tenant/id/uid/name) arrives on the job
// args, so the worker never rediscovers the domain by name and never creates it
// — discovered domains are created by EnumerateSubdomainWorker, user domains by
// the API handler. Observation emission and authoritative deletes are layered on
// in Phase 2.
func (w *ResolveDomainWorker) Work(ctx context.Context, job *river.Job[ResolveDomainArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	dnsClient := dnsclient.New()

	domainName := job.Args.DomainName
	domainID := pgtype.Int4{Int32: job.Args.DomainID, Valid: true}

	result := dnsclient.SubdomainResult{Name: domainName}

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
		{&result.DS, dnsClient.LookupDS},
		{&result.RRSIG, dnsClient.LookupRRSIG},
	}

	for _, l := range lookups {
		if records, ok := l.lookup(domainName + "."); ok && len(records) > 0 {
			*l.field = records
		}
	}

	records := []struct {
		parser  func(string, string) (interface{}, error)
		name    string
		entries []string
	}{
		{func(d, r string) (interface{}, error) { return dnsrecords.ParseA(d, r) }, "A", result.A},
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
		{func(d, r string) (interface{}, error) { return dnsrecords.ParseNS(d, r) }, "NS", result.NS},
		{func(d, r string) (interface{}, error) { return dnsrecords.ParseMX(d, r) }, "MX", result.MX},
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
		{func(d, r string) (interface{}, error) { return dnsrecords.ParseDS(d, r) }, "DS", result.DS},
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
			parsed, err := r.parser(domainName, entry)
			if err != nil {
				w.Logger.ErrorContext(ctx, "failed to parse record",
					"type", r.name,
					"domain", domainName,
					"error", err)
				continue
			}
			w.Logger.InfoContext(ctx, "parsed record", "parsed", parsed, "type", r.name)
			switch r.name {
			case "A":
				a, err := w.Store.RecordsCreateA(ctx, store.RecordsCreateAParams{
					DomainID:    domainID,
					Ipv4Address: entry,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found A record",
					"ip", a.Ipv4Address, "uid", a.Uid, "domain", domainName)
			case "AAAA":
				aaaa, err := w.Store.RecordsCreateAAAA(ctx, store.RecordsCreateAAAAParams{
					DomainID:    domainID,
					Ipv6Address: entry,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found AAAA record",
					"ipv6", aaaa.Ipv6Address, "uid", aaaa.Uid, "domain", domainName)
			case "CNAME":
				cname, err := w.Store.RecordsCreateCNAME(ctx, store.RecordsCreateCNAMEParams{
					DomainID: domainID,
					Target:   entry,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found CNAME record",
					"target", cname.Target, "uid", cname.Uid, "domain", domainName)
			case "MX":
				mv, err := dnsrecords.ParseMX(domainName, entry)
				if err != nil {
					return err
				}
				mx, err := w.Store.RecordsCreateMX(ctx, store.RecordsCreateMXParams{
					DomainID:   domainID,
					Preference: int32(mv.Preference),
					Target:     mv.Target,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found MX record",
					"record", mx, "uid", mx.Uid, "domain", domainName)
			case "TXT":
				txt, err := w.Store.RecordsCreateTXT(ctx, store.RecordsCreateTXTParams{
					DomainID: domainID,
					Value:    entry,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found TXT record",
					"value", txt.Value, "uid", txt.Uid, "domain", domainName)
			case "NS":
				ns, err := w.Store.RecordsCreateNS(ctx, store.RecordsCreateNSParams{
					DomainID:   domainID,
					Nameserver: entry,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found NS record",
					"nameserver", ns.Nameserver, "uid", ns.Uid, "domain", domainName)
			case "PTR":
				ptr, err := w.Store.RecordsCreatePTR(ctx, store.RecordsCreatePTRParams{
					DomainID: domainID,
					Target:   entry,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found PTR record",
					"target", ptr.Target, "uid", ptr.Uid, "domain", domainName)
			case "SRV":
				sv, err := dnsrecords.ParseSRV(domainName, entry)
				if err != nil {
					return err
				}
				srv, err := w.Store.RecordsCreateSRV(ctx, store.RecordsCreateSRVParams{
					DomainID: domainID,
					Target:   sv.Target,
					Port:     int32(sv.Port),
					Weight:   int32(sv.Weight),
					Priority: int32(sv.Priority),
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found SRV record",
					"record", srv, "uid", srv.Uid, "domain", domainName)
			case "CAA":
				cv, err := dnsrecords.ParseCAA(domainName, entry)
				if err != nil {
					return err
				}
				caa, err := w.Store.RecordsCreateCAA(ctx, store.RecordsCreateCAAParams{
					DomainID: domainID,
					Flags:    int32(cv.Flag),
					Tag:      cv.Tag,
					Value:    cv.Value,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found CAA record",
					"record", caa, "uid", caa.Uid, "domain", domainName)
			case "DNSKEY":
				ds, err := dnsrecords.ParseDNSKEY(domainName, entry)
				if err != nil {
					return err
				}
				dnskey, err := w.Store.RecordsCreateDNSKEY(ctx, store.RecordsCreateDNSKEYParams{
					DomainID:  domainID,
					PublicKey: ds.PublicKey,
					Flags:     int32(ds.Flags),
					Protocol:  int32(ds.Protocol),
					Algorithm: int32(ds.Algorithm),
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found DNSKEY record",
					"record", dnskey, "uid", dnskey.Uid, "domain", domainName)
			case "SOA":
				sv, err := dnsrecords.ParseSOARecord(domainName, entry)
				if err != nil {
					return err
				}
				soa, err := w.Store.RecordsCreateSOA(ctx, store.RecordsCreateSOAParams{
					DomainID:   domainID,
					Nameserver: sv.NameServer,
					Email:      sv.AdminEmail,
					Serial:     int64(sv.Serial),
					Refresh:    int32(sv.Refresh),
					Retry:      int32(sv.Retry),
					Expire:     int32(sv.Expire),
					MinimumTtl: int32(sv.MinimumTTL),
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found SOA record",
					"record", soa, "uid", soa.Uid, "domain", domainName)
			case "DS":
				dv, err := dnsrecords.ParseDS(domainName, entry)
				if err != nil {
					return err
				}
				ds, err := w.Store.RecordsCreateDS(ctx, store.RecordsCreateDSParams{
					DomainID:   domainID,
					KeyTag:     int32(dv.KeyTag),
					Algorithm:  int32(dv.Algorithm),
					DigestType: int32(dv.DigestType),
					Digest:     dv.Digest,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found DS record",
					"record", ds, "uid", ds.Uid, "domain", domainName)
			case "RRSIG":
				rv, err := dnsrecords.ParseRRSIG(domainName, entry)
				if err != nil {
					return err
				}
				rrsig, err := w.Store.RecordsCreateRRSIG(ctx, store.RecordsCreateRRSIGParams{
					DomainID:    domainID,
					TypeCovered: int32(rv.TypeCovered),
					Algorithm:   int32(rv.Algorithm),
					Labels:      int32(rv.Labels),
					OriginalTtl: int32(rv.OriginalTTL),
					Expiration:  int32(rv.Expiration),
					Inception:   int32(rv.Inception),
					KeyTag:      int32(rv.KeyTag),
					SignerName:  rv.SignerName,
					Signature:   rv.Signature,
				})
				if err != nil {
					return err
				}
				w.Logger.DebugContext(ctx, "found RRSIG record",
					"record", rrsig, "uid", rrsig.Uid, "domain", domainName)
			}
		}
	}

	if len(result.TXT) > 0 {
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
		_, err = rc.InsertTx(ctx, tx, AssessEmailSecurityArgs{DomainJobArgs: job.Args.DomainJobArgs}, nil)
		if err != nil {
			w.Logger.WarnContext(ctx, "failed to queue email security assessment",
				"domain", job.Args.DomainUID, "error", err)
		}
		return tx.Commit(ctx)
	}

	return nil
}
