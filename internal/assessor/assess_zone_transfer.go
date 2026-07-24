package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// AssessZoneTransfer performs a security assessment of DNS zone transfer capabilities for a given domain.
// It retrieves zone transfer attempts, analyzes the results, and stores findings related to potential
// DNS information exposure risks. Returns an error if the assessment process fails.
func (a *Assessor) AssessZoneTransfer(ctx context.Context, domainUID string) error {
	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: a.identity.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			a.logger.WarnContext(
				ctx,
				"Domain not found in database, cannot scan zone transfer",
				"domain",
				domain.Uid,
			)
			return fmt.Errorf("domain %s not found in database", domain.Uid)
		}
		a.logger.ErrorContext(ctx, "Error looking up domain", "domain", domain.Uid, "error", err)
		return err
	}
	attempts, err := a.store.ScannersGetZoneTransferAttempts(
		ctx,
		pgtype.Int4{Int32: domain.ID, Valid: true},
	)
	if err != nil {
		a.logger.ErrorContext(ctx, "Failed to retrieve zone transfer attempts", "error", err)
		return err
	}
	ev := detect.ZoneTransferEvidence{}
	for _, attempt := range attempts {
		ev.Attempts = append(ev.Attempts, detect.ZoneTransferAttemptEvidence{
			Nameserver:   attempt.Nameserver,
			TransferType: string(attempt.TransferType),
			Successful:   attempt.WasSuccessful,
			ResponseData: attempt.ResponseData,
		})
	}
	res, err := detect.ZoneTransferDetector{}.Detect(ev)
	if err != nil {
		return err
	}
	return a.reconcile(ctx, domain.ID, domain.Name, detect.CheckZoneTransfer, res)
}
