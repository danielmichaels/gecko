package scanner

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// ScanZoneTransfer attempts to perform a DNS zone transfer for a given domain name.
// It retrieves the domain from the database, attempts zone transfer using a DNS client,
// and stores the results of successful and unsuccessful transfer attempts.
// Returns the domain's unique identifier or an error if the scan fails.
func (s *Scan) ScanZoneTransfer(ctx context.Context, domainName string) (string, error) {
	domain, err := s.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		Name:     domainName,
		TenantID: pgtype.Int4{Int32: 1, Valid: true}, // todo: replace with actual tenant ID
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Warn("Domain not found in database, cannot scan zone transfer", "domain", domain)
			return "", fmt.Errorf("domain %s not found in database", domain.Uid)
		}
		s.logger.Error("Error looking up domain", "domain", domain.Uid, "error", err)
		return "", err
	}

	client := dnsclient.NewDNSClient()
	result := client.AttemptZoneTransfer(domainName)
	for nameserver, transferType := range result.SuccessfulTransfers {
		// Convert to assessment-friendly format
		data := result.ToAssessmentData()
		data.Nameserver = nameserver
		data.TransferType = transferType

		js, err := json.Marshal(data)
		if err != nil {
			s.logger.Error("Failed to marshal zone transfer data to JSON", "error", err)
			continue
		}

		err = s.store.ScannersStoreZoneTransferAttempt(ctx, store.ScannersStoreZoneTransferAttemptParams{
			DomainID:      pgtype.Int4{Int32: domain.ID, Valid: true},
			Nameserver:    nameserver,
			TransferType:  store.TransferType(transferType),
			WasSuccessful: true,
			ResponseData:  js,
		})
		if err != nil {
			s.logger.Error("Failed to store successful zone transfer attempt", "error", err)
		}
	}

	// Store failed zone transfer attempts
	for _, ns := range result.NS {
		nsAddr := ns + ":53"
		if _, found := result.SuccessfulTransfers[nsAddr]; !found {
			err := s.store.ScannersStoreZoneTransferAttempt(ctx, store.ScannersStoreZoneTransferAttemptParams{
				DomainID:      pgtype.Int4{Int32: domain.ID, Valid: true},
				Nameserver:    nsAddr,
				TransferType:  store.TransferTypeAXFRIXFR,
				WasSuccessful: false,
				ErrorMessage:  pgtype.Text{String: "Transfer refused or failed", Valid: true},
			})
			if err != nil {
				s.logger.Error("Failed to store failed zone transfer attempt", "error", err, "domain", domain.Uid)
			}
		}
	}

	return domain.Uid, nil
}
