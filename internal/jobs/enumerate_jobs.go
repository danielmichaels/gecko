package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

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

func (w *EnumerateSubdomainWorker) Timeout(*river.Job[EnumerateSubdomainArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *EnumerateSubdomainWorker) Work(
	ctx context.Context,
	job *river.Job[EnumerateSubdomainArgs],
) (enumErr error) {
	dnsClient := dnsclient.NewDNSClient()
	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func(tx pgx.Tx, ctx context.Context) {
		if enumErr != nil {
			err := tx.Rollback(ctx)
			if err != nil {
				w.Logger.Error("transaction rollback", "error", err)
			}
		}
	}(tx, ctx)

	rc := river.ClientFromContext[pgx.Tx](ctx)

	err = dnsClient.EnumerateWithSubfinderCallback(
		ctx,
		job.Args.Domain,
		job.Args.Concurrency,
		func(entry *resolve.HostEntry) {
			w.Logger.Info("enumerate_subdomain", "host", entry.Host)
			// future: do we recursively enumerate subdomains?
			// future: remove subfinder with gecko implementation
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

	err = tx.Commit(ctx)
	if err != nil {
		return err
	}
	return nil
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
		{&result.DS, dnsClient.LookupDS},
		{&result.RRSIG, dnsClient.LookupRRSIG},
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
			d, err := w.Store.DomainsCreate(ctx, store.DomainsCreateParams{
				TenantID:   pgtype.Int4{Int32: 1, Valid: true},
				Name:       result.Name,
				DomainType: store.DomainTypeSubdomain, // todo: need to actually confirm this is a subdomain
				Source:     store.DomainSourceUserSupplied,
				Status:     store.DomainStatusActive,
			})
			if err != nil {
				return err
			}
			switch r.name {
			case "A":
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
			case "AAAA":
				aaaa, err := w.Store.RecordsCreateAAAA(ctx, store.RecordsCreateAAAAParams{
					DomainID:    pgtype.Int4{Int32: d.ID, Valid: true},
					Ipv6Address: entry,
				})
				if err != nil {
					return err
				}
				w.Logger.Debug(
					"found AAAA record",
					"ipv6",
					aaaa.Ipv6Address,
					"uid",
					aaaa.Uid,
					"domain",
					d.Name,
				)

			case "CNAME":
				cname, err := w.Store.RecordsCreateCNAME(ctx, store.RecordsCreateCNAMEParams{
					DomainID: pgtype.Int4{Int32: d.ID, Valid: true},
					Target:   entry,
				})
				if err != nil {
					return err
				}
				w.Logger.Debug(
					"found CNAME record",
					"target",
					cname.Target,
					"uid",
					cname.Uid,
					"domain",
					d.Name,
				)

			case "MX":
				mv, err := dnsrecords.ParseMX(d.Name, entry)
				if err != nil {
					return err
				}
				mx, err := w.Store.RecordsCreateMX(ctx, store.RecordsCreateMXParams{
					DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
					Preference: int32(mv.Preference),
					Target:     mv.Target,
				})
				if err != nil {
					return err
				}
				w.Logger.Debug("found MX record", "record", mx, "uid", mx.Uid, "domain", d.Name)

			case "TXT":
				txt, err := w.Store.RecordsCreateTXT(ctx, store.RecordsCreateTXTParams{
					DomainID: pgtype.Int4{Int32: d.ID, Valid: true},
					Value:    entry,
				})
				if err != nil {
					return err
				}
				w.Logger.Debug(
					"found TXT record",
					"value",
					txt.Value,
					"uid",
					txt.Uid,
					"domain",
					d.Name,
				)

			case "NS":
				ns, err := w.Store.RecordsCreateNS(ctx, store.RecordsCreateNSParams{
					DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
					Nameserver: entry,
				})
				if err != nil {
					return err
				}
				w.Logger.Debug(
					"found NS record",
					"nameserver",
					ns.Nameserver,
					"uid",
					ns.Uid,
					"domain",
					d.Name,
				)

			case "PTR":
				ptr, err := w.Store.RecordsCreatePTR(ctx, store.RecordsCreatePTRParams{
					DomainID: pgtype.Int4{Int32: d.ID, Valid: true},
					Target:   entry,
				})
				if err != nil {
					return err
				}
				w.Logger.Debug(
					"found PTR record",
					"target",
					ptr.Target,
					"uid",
					ptr.Uid,
					"domain",
					d.Name,
				)

			case "SRV":
				sv, err := dnsrecords.ParseSRV(d.Name, entry)
				if err != nil {
					return err
				}
				srv, err := w.Store.RecordsCreateSRV(ctx, store.RecordsCreateSRVParams{
					DomainID: pgtype.Int4{Int32: d.ID, Valid: true},
					Target:   sv.Target,
					Port:     int32(sv.Port),
					Weight:   int32(sv.Weight),
					Priority: int32(sv.Priority),
				})
				if err != nil {
					return err
				}
				w.Logger.Debug("found SRV record", "record", srv, "uid", srv.Uid, "domain", d.Name)

			case "CAA":
				cv, err := dnsrecords.ParseCAA(d.Name, entry)
				if err != nil {
					return err
				}
				caa, err := w.Store.RecordsCreateCAA(ctx, store.RecordsCreateCAAParams{
					DomainID: pgtype.Int4{Int32: d.ID, Valid: true},
					Flags:    int32(cv.Flag),
					Tag:      cv.Tag,
					Value:    cv.Value,
				})
				if err != nil {
					return err
				}
				w.Logger.Debug("found CAA record", "record", caa, "uid", caa.Uid, "domain", d.Name)
			case "DNSKEY":
				ds, err := dnsrecords.ParseDNSKEY(d.Name, entry)
				if err != nil {
					return err
				}
				dnskey, err := w.Store.RecordsCreateDNSKEY(ctx, store.RecordsCreateDNSKEYParams{
					DomainID:  pgtype.Int4{Int32: d.ID, Valid: true},
					PublicKey: ds.PublicKey,
					Flags:     int32(ds.Flags),
					Protocol:  int32(ds.Protocol),
					Algorithm: int32(ds.Algorithm),
				})
				if err != nil {
					return err
				}
				w.Logger.Debug(
					"found DNSKEY record",
					"record",
					dnskey,
					"uid",
					dnskey.Uid,
					"domain",
					d.Name,
				)

			case "SOA":
				sv, err := dnsrecords.ParseSOARecord(d.Name, entry)
				if err != nil {
					return err
				}
				soa, err := w.Store.RecordsCreateSOA(ctx, store.RecordsCreateSOAParams{
					DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
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
				w.Logger.Debug("found SOA record", "record", soa, "uid", soa.Uid, "domain", d.Name)

			case "DS":
				dv, err := dnsrecords.ParseDS(d.Name, entry)
				if err != nil {
					return err
				}
				ds, err := w.Store.RecordsCreateDS(ctx, store.RecordsCreateDSParams{
					DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
					KeyTag:     int32(dv.KeyTag),
					Algorithm:  int32(dv.Algorithm),
					DigestType: int32(dv.DigestType),
					Digest:     dv.Digest,
				})
				if err != nil {
					return err
				}
				w.Logger.Debug("found DS record", "record", ds, "uid", ds.Uid, "domain", d.Name)

			case "RRSIG":
				// fixme: this isn't working as expected; SERVFAIL issues
				rv, err := dnsrecords.ParseRRSIG(d.Name, entry)
				if err != nil {
					return err
				}
				rrsig, err := w.Store.RecordsCreateRRSIG(ctx, store.RecordsCreateRRSIGParams{
					DomainID:    pgtype.Int4{Int32: d.ID, Valid: true},
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
				w.Logger.Debug(
					"found RRSIG record",
					"record",
					rrsig,
					"uid",
					rrsig.Uid,
					"domain",
					d.Name,
				)
			}
		}
	}

	return nil
}
