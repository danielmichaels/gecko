package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

func (a *Assessor) AssessZoneTransfer(ctx context.Context, domainUID string) error {
	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: 1, Valid: true}, // todo: replace with actual tenant ID
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			a.logger.Warn("Domain not found in database, cannot scan zone transfer", "domain", domain.Uid)
			return fmt.Errorf("domain %s not found in database", domain.Uid)
		}
		a.logger.Error("Error looking up domain", "domain", domain.Uid, "error", err)
		return err
	}
	attempts, err := a.store.ScannersGetZoneTransferAttempts(ctx, pgtype.Int4{Int32: domain.ID, Valid: true})
	if err != nil {
		a.logger.Error("Failed to retrieve zone transfer attempts", "error", err)
		return err
	}

	// Analyze the data and generate findings
	for _, attempt := range attempts {
		if attempt.WasSuccessful {
			// Create a HIGH severity finding - zone transfer allowed
			err = a.store.StoreZoneTransferFinding(ctx, store.StoreZoneTransferFindingParams{
				DomainID:             pgtype.Int4{Int32: domain.ID, Valid: true},
				Severity:             store.FindingSeverityCritical, // todo check this
				Status:               store.FindingStatusOpen,       // todo check this
				Nameserver:           attempt.Nameserver,
				ZoneTransferPossible: true,
				TransferType:         attempt.TransferType,
				Details:              pgtype.Text{String: fmt.Sprintf("Zone transfer (%s) allowed from this nameserver. This can leak DNS zone information to attackers.", attempt.TransferType), Valid: true},
			})
			if err != nil {
				a.logger.Error("Failed to store zone transfer finding", "error", err)
			}
		}
	}

	return nil
}
