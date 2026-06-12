package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/tracing"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
)

// DomainJobArgs is the stable domain identity stamped onto every leaf scan job.
// Workers never rediscover the domain by name (no DomainsGetByName); the recorder
// stamps tenant_id/domain_* onto observations directly from these fields.
type DomainJobArgs struct {
	DomainUID  string `json:"domain_uid"`
	DomainName string `json:"domain_name"`
	ScanID     int64  `json:"scan_id"`
	TenantID   int32  `json:"tenant_id"`
	DomainID   int32  `json:"domain_id"`
}

// Identity maps the job's domain args onto the observer's identity, used to
// stamp observations emitted by the scanner/assessor.
func (a DomainJobArgs) Identity() observer.DomainIdentity {
	return observer.DomainIdentity{
		TenantID:   a.TenantID,
		DomainID:   a.DomainID,
		DomainUID:  a.DomainUID,
		DomainName: a.DomainName,
		ScanID:     a.ScanID,
	}
}

// DomainScanTarget is the identity of the domain to scan, passed into
// EnqueueDomainScan. Status drives the active-status gate.
type DomainScanTarget struct {
	DomainUID  string
	DomainName string
	Status     store.DomainStatus
	TenantID   int32
	DomainID   int32
}

// DomainScanOptions controls a single scan enqueue.
type DomainScanOptions struct {
	// ParentScanID links this scan to the apex scan that discovered it, so the
	// timeline can group child scans under their parent.
	ParentScanID *int64
	// Source is the scan trigger: 'user_supplied'/'discovered' mirror the domain's
	// origin, 'scheduled' is set only by the periodic scheduler.
	Source store.ScanSource
	// RecencyWindow: a discovered domain scanned more recently than this is
	// skipped (dedup). Ignored when Force is set.
	RecencyWindow time.Duration
	// Concurrency is passed through to subdomain enumeration.
	Concurrency int
	// EnumerateSubdomains additionally enqueues a subdomain-enumeration job.
	EnumerateSubdomains bool
	// Force bypasses the recency guard for explicit user actions (POST/PUT/manual
	// rescan). Force does NOT bypass the active-status gate.
	Force bool
}

// EnqueueDomainScan is the single entry point for scheduling a domain scan. It
// creates a scans correlation row and enqueues every leaf job carrying the
// domain identity, all within the caller's transaction. It returns the new
// scan id, or 0 when the scan was skipped (inactive domain, or recency dedup).
//
// rc is the River client (app.RC in handlers, river.ClientFromContext in
// workers); st must be transaction-scoped (store.New(pool).WithTx(tx)).
func EnqueueDomainScan(
	ctx context.Context,
	rc *river.Client[pgx.Tx],
	tx pgx.Tx,
	st *store.Queries,
	target DomainScanTarget,
	opts DomainScanOptions,
) (int64, error) {
	// Ensure a trace ID exists for the whole scan tree: inherit the caller's
	// (e.g. the HTTP request that triggered the scan) or mint one. Every leaf job
	// enqueued below is stamped with it by CorrelationInsertHook, so the entire
	// scan — and the jobs each worker spawns — share one correlation ID.
	ctx = tracing.WithNewTraceID(ctx, false)

	// Active-status gate: an explicitly inactive domain is never scanned, even
	// when Force is set. Force means "ignore recency", not "ignore inactive".
	if target.Status != store.DomainStatusActive {
		return 0, nil
	}

	// Serialize concurrent enqueues for this domain so the recency check and the
	// scan insert are atomic against a racing enumeration discovering the same host.
	if err := st.AcquireDomainScanLock(ctx, int64(target.DomainID)); err != nil {
		return 0, fmt.Errorf("acquire domain scan lock: %w", err)
	}

	if !opts.Force {
		recent, err := st.ScansGetRecentByTenantDomainName(
			ctx,
			store.ScansGetRecentByTenantDomainNameParams{
				TenantID:   target.TenantID,
				DomainName: target.DomainName,
			},
		)
		switch {
		case err == nil:
			if recent.StartedAt.Valid &&
				time.Since(recent.StartedAt.Time) < opts.RecencyWindow {
				return 0, nil // scanned recently; dedup
			}
		case errors.Is(err, pgx.ErrNoRows):
			// never scanned; proceed
		default:
			return 0, fmt.Errorf("scan recency check: %w", err)
		}
	}

	var parent pgtype.Int8
	if opts.ParentScanID != nil {
		parent = pgtype.Int8{Int64: *opts.ParentScanID, Valid: true}
	}
	scan, err := st.ScansCreate(ctx, store.ScansCreateParams{
		TenantID:     target.TenantID,
		DomainID:     pgtype.Int4{Int32: target.DomainID, Valid: true},
		DomainUid:    target.DomainUID,
		DomainName:   target.DomainName,
		ParentScanID: parent,
		Source:       opts.Source,
	})
	if err != nil {
		return 0, fmt.Errorf("create scan: %w", err)
	}

	ident := DomainJobArgs{
		TenantID:   target.TenantID,
		DomainID:   target.DomainID,
		DomainUID:  target.DomainUID,
		DomainName: target.DomainName,
		ScanID:     scan.ID,
	}
	params := []river.InsertManyParams{
		{Args: ResolveDomainArgs{DomainJobArgs: ident}},
		{Args: ScanCertificateArgs{DomainJobArgs: ident}},
		{Args: ScanCNAMEArgs{DomainJobArgs: ident}},
		{Args: ScanDNSSECArgs{DomainJobArgs: ident}},
		{Args: ScanZoneTransferArgs{DomainJobArgs: ident}},
	}
	if opts.EnumerateSubdomains {
		params = append(params, river.InsertManyParams{
			Args: EnumerateSubdomainArgs{DomainJobArgs: ident, Concurrency: opts.Concurrency},
		})
	}
	if _, err := rc.InsertManyTx(ctx, tx, params); err != nil {
		return 0, fmt.Errorf("enqueue scan jobs: %w", err)
	}

	// Chokepoint stamp: every scan that reaches this point — manual, discovered, or
	// scheduled — records the real last-scan time and advances the scheduling
	// cursor by the domain's effective cadence (override ?? tenant default). This is
	// the single place that keeps last_scanned_at honest across all triggers and
	// resets the cadence clock from the actual scan; an 'off' effective frequency
	// clears the cursor so the domain stays out of the schedule.
	freqs, err := st.DomainsGetScanFrequencies(ctx, target.DomainID)
	if err != nil {
		return 0, fmt.Errorf("read scan frequencies: %w", err)
	}
	baseSecs, isOff := ScheduleArgs(
		EffectiveFrequency(freqs.ScanFrequency, freqs.DefaultScanFrequency),
	)
	if err := st.DomainsMarkScanned(ctx, store.DomainsMarkScannedParams{
		IsOff:    isOff,
		BaseSecs: baseSecs,
		DomainID: target.DomainID,
	}); err != nil {
		return 0, fmt.Errorf("mark scanned: %w", err)
	}

	return scan.ID, nil
}
