package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	CertExpiry           = "certificate_expiry"
	CertWeakKey          = "certificate_weak_key"
	CertSelfSigned       = "certificate_self_signed"
	CertHostnameMismatch = "certificate_hostname_mismatch"

	// MinRSAKeyStrength is the minimum acceptable RSA modulus size in bits.
	MinRSAKeyStrength = 2048
)

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

	cert, err := a.store.ScannersGetCertificate(ctx, pgtype.Int4{Int32: domain.ID, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			a.logger.InfoContext(ctx, "No certificate to assess", "domain", domain.Uid)
			return nil
		}
		a.logger.ErrorContext(ctx, "Failed to retrieve certificate", "error", err)
		return err
	}

	cfg := config.AppConfig()
	certID := pgtype.Int4{Int32: cert.ID, Valid: true}

	severity, status, details := evaluateExpiry(cert.NotAfter.Time, cfg)
	if err := a.createCertFinding(ctx, domain.ID, certID, severity, status, CertExpiry, details); err != nil {
		return err
	}

	if isWeakKey(cert.KeyAlgorithm, cert.KeyStrength) {
		details := fmt.Sprintf("%s key strength %d is below the minimum of %d bits",
			cert.KeyAlgorithm, cert.KeyStrength, MinRSAKeyStrength)
		if err := a.createCertFinding(ctx, domain.ID, certID,
			store.FindingSeverityHigh, store.FindingStatusOpen, CertWeakKey, details); err != nil {
			return err
		}
	}

	if isSelfSigned(cert.Issuer, cert.Subject) {
		details := fmt.Sprintf(
			"Certificate issuer and subject are identical (%s); chain is self-signed",
			cert.Subject,
		)
		if err := a.createCertFinding(ctx, domain.ID, certID,
			store.FindingSeverityMedium, store.FindingStatusOpen, CertSelfSigned, details); err != nil {
			return err
		}
	}

	if !hostnameCovered(domain.Name, cert.Sans, cert.DnsNames) {
		details := fmt.Sprintf("Domain %s is not covered by the certificate SANs", domain.Name)
		if err := a.createCertFinding(ctx, domain.ID, certID,
			store.FindingSeverityHigh, store.FindingStatusOpen, CertHostnameMismatch, details); err != nil {
			return err
		}
	}

	a.logger.InfoContext(ctx, "Successfully assessed certificate", "domain", domain.Uid)
	return nil
}

// evaluateExpiry maps the certificate not_after date onto a severity tier. An
// already-expired certificate is critical; the High/Medium day windows are
// config-driven; anything beyond is compliant.
func evaluateExpiry(
	notAfter time.Time,
	cfg *config.Conf,
) (store.FindingSeverity, store.FindingStatus, string) {
	now := time.Now()
	if notAfter.Before(now) {
		return store.FindingSeverityCritical, store.FindingStatusOpen,
			fmt.Sprintf("Certificate expired on %s", notAfter.Format(time.RFC3339))
	}
	daysLeft := int(notAfter.Sub(now).Hours() / 24)
	switch {
	case daysLeft < cfg.AppConf.CertExpiryHighDays:
		return store.FindingSeverityHigh, store.FindingStatusOpen,
			fmt.Sprintf("Certificate expires in %d days", daysLeft)
	case daysLeft < cfg.AppConf.CertExpiryMediumDays:
		return store.FindingSeverityMedium, store.FindingStatusOpen,
			fmt.Sprintf("Certificate expires in %d days", daysLeft)
	default:
		return store.FindingSeverityInfo, store.FindingStatusCompliant,
			fmt.Sprintf("Certificate valid until %s", notAfter.Format(time.RFC3339))
	}
}

func isWeakKey(algorithm string, strength int32) bool {
	return strings.EqualFold(algorithm, "RSA") && strength < MinRSAKeyStrength
}

func isSelfSigned(issuer, subject string) bool {
	return issuer != "" && issuer == subject
}

// hostnameCovered reports whether the domain is matched by any certificate SAN
// or DNS name, honouring single-label wildcard prefixes (*.example.com).
func hostnameCovered(domain string, sans, dnsNames []string) bool {
	host := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, name := range append(append([]string{}, sans...), dnsNames...) {
		if hostMatchesName(host, name) {
			return true
		}
	}
	return false
}

func hostMatchesName(host, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == host {
		return true
	}
	if strings.HasPrefix(name, "*.") {
		suffix := name[1:] // ".example.com"
		if label, found := strings.CutSuffix(host, suffix); found {
			return label != "" && !strings.Contains(label, ".")
		}
	}
	return false
}

func (a *Assessor) createCertFinding(
	ctx context.Context,
	domainID int32,
	certID pgtype.Int4,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType, details string,
) error {
	if _, err := a.store.AssessCreateCertificateFinding(ctx, store.AssessCreateCertificateFindingParams{
		DomainID:      pgtype.Int4{Int32: domainID, Valid: true},
		CertificateID: certID,
		Severity:      severity,
		Status:        status,
		IssueType:     issueType,
		Details:       pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(
			ctx,
			"failed to create certificate finding",
			"issue_type",
			issueType,
			"error",
			err,
		)
		return fmt.Errorf("create certificate finding %s: %w", issueType, err)
	}

	payload := observer.PayloadJSON(map[string]any{
		"issue_type": issueType,
		"severity":   string(severity),
		"status":     string(status),
		"details":    details,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityCertificateFinding, issueType, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit certificate finding observation",
			"issue_type", issueType, "error", oErr)
	}
	return nil
}
