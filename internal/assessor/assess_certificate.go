package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// MinRSAKeyStrength is the minimum acceptable RSA modulus size in bits.
const MinRSAKeyStrength = 2048

// AssessCertificate interprets the stored TLS certificate for a domain and
// records findings for expiry, weak keys, self-signed chains, and hostname
// mismatch. Expiry is emitted with a stable issue_type so its severity can
// transition across scans as the not_after date approaches.
func (a *Assessor) AssessCertificate(ctx context.Context, domainUID string) error {
	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: a.identity.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("domain %s not found in database", domainUID)
		}
		a.logger.ErrorContext(ctx, "Error looking up domain", "domain", domainUID, "error", err)
		return err
	}

	ev := detect.CertificateEvidence{DomainName: domain.Name, ObservedAt: time.Now()}
	cert, err := a.store.ScannersGetCertificate(ctx, pgtype.Int4{Int32: domain.ID, Valid: true})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No certificate collected -> Fetched stays false -> detector emits nothing
		// (unknown, not "fine"). Reconcile still runs so a previously-open cert
		// finding resolves once the cert is gone.
	case err != nil:
		a.logger.ErrorContext(ctx, "Failed to retrieve certificate", "error", err)
		return err
	default:
		ev.Fetched = true
		ev.NotAfter = cert.NotAfter.Time
		ev.KeyAlgorithm = cert.KeyAlgorithm
		ev.KeyStrength = cert.KeyStrength
		ev.Issuer = cert.Issuer
		ev.Subject = cert.Subject
		ev.SANs = cert.Sans
		ev.DNSNames = cert.DnsNames
	}

	cfg := config.AppConfig()
	found, err := detect.CertificateDetector{
		ExpiryHighDays:   cfg.AppConf.CertExpiryHighDays,
		ExpiryMediumDays: cfg.AppConf.CertExpiryMediumDays,
		MinRSAKeyBits:    MinRSAKeyStrength,
	}.Detect(ev)
	if err != nil {
		return err
	}
	return a.reconcile(ctx, domain.Name, detect.CheckCertificate, found)
}
