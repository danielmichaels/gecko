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

type ScanSOAArgs struct {
	Domain string `json:"domain"`
}

func (ScanSOAArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanSOAArgs) Kind() string { return "scan_soa" }

type ScanSOAWorker struct {
	Logger slog.Logger
	Store  *store.Queries
	river.WorkerDefaults[ScanSOAArgs]
}

func (w *ScanSOAWorker) Work(ctx context.Context, job *river.Job[ScanSOAArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()

	result := scanner.ScanSOA(job.Args.Domain)

	w.Logger.InfoContext(ctx,
		"soa scan complete",
		"domain", job.Args.Domain,
		"duration", time.Since(start),
	)
	fmt.Printf("SOA scan complete for: %q\n%+v\n", job.Args.Domain, result)
	return nil
}
