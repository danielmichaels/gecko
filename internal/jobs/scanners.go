package jobs

import (
	"context"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/scanner"
	"github.com/danielmichaels/doublestag/internal/store"
	"github.com/danielmichaels/doublestag/internal/tracing"
	"github.com/riverqueue/river"
	"log/slog"
	"time"
)

type ScanCertificateArgs struct {
	Domain string `json:"domain"`
}

func (ScanCertificateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanCertificateArgs) Kind() string { return "scan_certificate" }

type ScanCertificateWorker struct {
	Logger slog.Logger
	Store  *store.Queries
	river.WorkerDefaults[ScanCertificateArgs]
}

func (w *ScanCertificateWorker) Work(ctx context.Context, job *river.Job[ScanCertificateArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()

	result := scanner.ScanCertificate(job.Args.Domain)
	w.Logger.InfoContext(ctx,
		"certificate scan complete",
		"domain", job.Args.Domain,
		"duration", time.Since(start),
	)
	fmt.Printf("Certificate scan complete for: %q\n%+v\n", job.Args.Domain, result)
	return nil
}

type ScanCNAMEArgs struct {
	Domain string `json:"domain"`
}

func (ScanCNAMEArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanCNAMEArgs) Kind() string { return "scan_cname" }

type ScanCNAMEWorker struct {
	Logger slog.Logger
	Store  *store.Queries
	river.WorkerDefaults[ScanCNAMEArgs]
}

func (w *ScanCNAMEWorker) Work(ctx context.Context, job *river.Job[ScanCNAMEArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()

	result := scanner.ScanCNAME(job.Args.Domain)

	w.Logger.InfoContext(ctx,
		"cname scan complete",
		"domain", job.Args.Domain,
		"duration", time.Since(start),
	)
	fmt.Printf("CNAME (dangling) scan complete for: %q\n%+v\n", job.Args.Domain, result)
	return nil
}

type ScanDNSSECArgs struct {
	Domain string `json:"domain"`
}

func (ScanDNSSECArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanDNSSECArgs) Kind() string { return "scan_dnssec" }

type ScanDNSSECWorker struct {
	Logger slog.Logger
	Store  *store.Queries
	river.WorkerDefaults[ScanDNSSECArgs]
}

func (w *ScanDNSSECWorker) Work(ctx context.Context, job *river.Job[ScanDNSSECArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()
	result := scanner.ScanDNSSEC(job.Args.Domain)

	w.Logger.InfoContext(ctx,
		"dnssec scan complete",
		"domain", job.Args.Domain,
		"duration", time.Since(start),
		"result", result,
	)
	// todo: do something with the result
	return nil
}

type ScanZoneTransferArgs struct {
	Domain string `json:"domain"`
}

func (ScanZoneTransferArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanZoneTransferArgs) Kind() string { return "scan_zone_transfer" }

type ScanZoneTransferWorker struct {
	Logger slog.Logger
	Store  *store.Queries
	river.WorkerDefaults[ScanZoneTransferArgs]
}

func (w *ScanZoneTransferWorker) Work(ctx context.Context, job *river.Job[ScanZoneTransferArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()

	result := scanner.ScanZoneTransfer(job.Args.Domain)

	w.Logger.InfoContext(ctx,
		"zone transfer scan complete",
		"domain", job.Args.Domain,
		"vulnerable", result.Vulnerable,
		"nameservers", result.NS,
		"duration", time.Since(start),
	)

	if result.Vulnerable {
		// todo: insert to DB here
		w.Logger.WarnContext(ctx,
			"zone transfer vulnerability detected",
			"domain", job.Args.Domain,
			"nameservers", result.NS,
			"successful_transfers", result.SuccessfulTransfers,
		)
	} else {
		w.Logger.InfoContext(ctx, "zone transfer not possible", "domain", job.Args.Domain, "ns", result.NS)
	}

	return nil
}
