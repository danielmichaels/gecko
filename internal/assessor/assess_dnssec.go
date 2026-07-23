package assessor

import (
	"context"
	"database/sql"
	"errors"

	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/scanner"
	"github.com/jackc/pgx/v5/pgtype"
)

// AssessDNSSEC interprets the stored DNSSEC scan state and records findings that
// distinguish absent DNSSEC (informational) from a broken chain of trust (an
// availability risk) and from a deprecated signing algorithm.
func (a *Assessor) AssessDNSSEC(ctx context.Context, domainUID string) error {
	domain, err := a.getDomain(ctx, domainUID)
	if err != nil {
		return err
	}

	ev := detect.DNSSECEvidence{}
	result, err := a.store.ScannersGetDNSSECResult(ctx, pgtype.Int4{Int32: domain.ID, Valid: true})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No scan result -> Fetched false -> detector emits nothing; reconcile still
		// resolves any previously-open dnssec finding.
	case err != nil:
		a.logger.ErrorContext(ctx, "Failed to retrieve DNSSEC scan result", "error", err)
		return err
	default:
		ev.Fetched = true
		ev.NotApplicable = result.Status == scanner.DNSSECNotApplicable
		if result.ValidationError.Valid {
			ev.ValidationError = result.ValidationError.String
		}
		ev.HasDNSKEY = result.HasDnskey
		ev.HasDS = result.HasDs
		ev.HasRRSIG = result.HasRrsig
		ev.Algorithms = result.Algorithms
	}

	found, err := detect.DNSSECDetector{}.Detect(ev)
	if err != nil {
		return err
	}
	return a.reconcile(ctx, domain.Name, detect.CheckDNSSEC, found)
}
