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

type DomainJobArgs struct {
	DomainUID  string `json:"domain_uid"`
	DomainName string `json:"domain_name"`
	ScanID     int64  `json:"scan_id"`
	TenantID   int32  `json:"tenant_id"`
	DomainID   int32  `json:"domain_id"`
}

func (a DomainJobArgs) Identity() observer.DomainIdentity {
	return observer.DomainIdentity{
		TenantID:   a.TenantID,
		DomainID:   a.DomainID,
		DomainUID:  a.DomainUID,
		DomainName: a.DomainName,
		ScanID:     a.ScanID,
	}
}

type DomainScanTarget struct {
	DomainUID  string
	DomainName string
	Status     store.DomainStatus
	TenantID   int32
	DomainID   int32
}

type DomainScanOptions struct {
	ParentScanID        *int64
	Source              store.ScanSource
	RecencyWindow       time.Duration
	Concurrency         int
	EnumerateSubdomains bool
	Force               bool
}

func EnqueueDomainScan(
	ctx context.Context,
	rc *river.Client[pgx.Tx],
	tx pgx.Tx,
	st *store.Queries,
	target DomainScanTarget,
	opts DomainScanOptions,
) (int64, error) {
	ctx = tracing.WithNewTraceID(ctx, false)

	if target.Status != store.DomainStatusActive {
		return 0, nil
	}

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
				return 0, nil
			}
		case errors.Is(err, pgx.ErrNoRows):
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
