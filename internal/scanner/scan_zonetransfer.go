package scanner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"strconv"
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
		s.logger.Error("Error looking up domain", "domain", domain, "error", err)
		return "", err
	}

	client := dnsclient.NewDNSClient()
	result := client.AttemptZoneTransfer(domainName)
	for nameserver, transferType := range result.SuccessfulTransfers {
		err := s.store.ScannersStoreZoneTransferAttempt(ctx, store.ScannersStoreZoneTransferAttemptParams{
			DomainID:      pgtype.Int4{Int32: domain.ID, Valid: true},
			Nameserver:    nameserver,
			TransferType:  store.TransferType(transferType),
			WasSuccessful: true,
			ResponseData:  pgtype.Text{String: formatTransferData(result, nameserver), Valid: true},
		})
		if err != nil {
			s.logger.Error("Failed to store successful zone transfer attempt", "error", err)
		}
	}

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
				s.logger.Error("Failed to store failed zone transfer attempt", "error", err)
			}
		}
	}

	return domain.Uid, nil
}

// formatTransferData converts a zone transfer result into a formatted string representation.
// It attempts to format the result using the FormatResult method, falling back to a simple
// record count if JSON encoding fails.
func formatTransferData(result *dnsrecords.ZoneTransferResult, nameserver string) string {
	formatted, err := result.FormatResult(nameserver)
	if err != nil {
		// If formatting fails, fallback to a simple record count
		return "Records received: " + strconv.Itoa(len(result.AXFR[nameserver])+len(result.IXFR[nameserver]))
	}

	return formatted
}
