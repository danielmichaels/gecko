// Package detect holds the pure Detectors and their typed evidence. A Detector
// interprets already-collected evidence into findings with no clock, network, or
// DB access -- every input it needs (including the reference time and any policy
// threshold) is passed in, so findings are table-driven-testable and re-runnable
// over stored evidence. Collectors (the outbound-I/O half) join in Phase 2.
package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/checks"
)

const CheckCertificate = "certificate"

const (
	IssueCertExpiry           = "certificate_expiry"
	IssueCertWeakKey          = "certificate_weak_key"
	IssueCertSelfSigned       = "certificate_self_signed"
	IssueCertHostnameMismatch = "certificate_hostname_mismatch"
)

// CertificateEvidence is the collected TLS certificate state for one asset.
// Fetched distinguishes "no certificate could be retrieved" (unknown -> emit
// nothing) from a real certificate whose fields are then judged. ObservedAt is the
// collection time expiry is measured against, keeping the detector clock-free.
type CertificateEvidence struct {
	ObservedAt   time.Time `json:"observed_at"`
	DomainName   string    `json:"domain_name"`
	KeyAlgorithm string    `json:"key_algorithm"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	NotAfter     time.Time `json:"not_after"`
	SANs         []string  `json:"sans"`
	DNSNames     []string  `json:"dns_names"`
	KeyStrength  int32     `json:"key_strength"`
	Fetched      bool      `json:"fetched"`
}

// CertificateDetector judges a certificate for expiry, weak keys, self-signed
// chains, and hostname mismatch. Its thresholds are injected (not read from a
// global) so Detect stays pure.
type CertificateDetector struct {
	ExpiryHighDays   int
	ExpiryMediumDays int
	MinRSAKeyBits    int32
}

func (CertificateDetector) Kind() string                { return CheckCertificate }
func (CertificateDetector) Scope() checks.EvidenceScope { return checks.SingleAsset }

// Detect returns the certificate problems true now. A cert that could not be
// fetched yields no findings (unknown, not "fine"); a healthy cert yields none.
func (d CertificateDetector) Detect(ev CertificateEvidence) ([]checks.Finding, error) {
	if !ev.Fetched {
		return nil, nil
	}
	var out []checks.Finding
	if f, ok := d.expiryFinding(ev); ok {
		out = append(out, f)
	}
	if isWeakRSAKey(ev.KeyAlgorithm, ev.KeyStrength, d.MinRSAKeyBits) {
		out = append(out, checks.Finding{
			IssueType: IssueCertWeakKey,
			Severity:  "high",
			Title:     "Weak certificate key",
			Details: fmt.Sprintf("%s key strength %d is below the minimum of %d bits",
				ev.KeyAlgorithm, ev.KeyStrength, d.MinRSAKeyBits),
		})
	}
	if isSelfSigned(ev.Issuer, ev.Subject) {
		out = append(out, checks.Finding{
			IssueType: IssueCertSelfSigned,
			Severity:  "medium",
			Title:     "Self-signed certificate",
			Details: fmt.Sprintf(
				"Certificate issuer and subject are identical (%s); chain is self-signed",
				ev.Subject),
		})
	}
	if !hostnameCovered(ev.DomainName, ev.SANs, ev.DNSNames) {
		out = append(out, checks.Finding{
			IssueType: IssueCertHostnameMismatch,
			Severity:  "high",
			Title:     "Certificate hostname mismatch",
			Details: fmt.Sprintf(
				"Domain %s is not covered by the certificate SANs",
				ev.DomainName,
			),
		})
	}
	return out, nil
}

// expiryFinding maps the not_after date onto a severity tier relative to the
// collection time. Expired is critical; the High/Medium day windows are injected;
// anything beyond is compliant and yields no finding (ok=false).
func (d CertificateDetector) expiryFinding(ev CertificateEvidence) (checks.Finding, bool) {
	if ev.NotAfter.Before(ev.ObservedAt) {
		return checks.Finding{
			IssueType: IssueCertExpiry,
			Severity:  "critical",
			Title:     "Certificate expired",
			Details:   "Certificate expired on " + ev.NotAfter.Format(time.RFC3339),
		}, true
	}
	daysLeft := int(ev.NotAfter.Sub(ev.ObservedAt).Hours() / 24)
	switch {
	case daysLeft < d.ExpiryHighDays:
		return checks.Finding{
			IssueType: IssueCertExpiry,
			Severity:  "high",
			Title:     "Certificate expiring soon",
			Details:   fmt.Sprintf("Certificate expires in %d days", daysLeft),
		}, true
	case daysLeft < d.ExpiryMediumDays:
		return checks.Finding{
			IssueType: IssueCertExpiry,
			Severity:  "medium",
			Title:     "Certificate expiring",
			Details:   fmt.Sprintf("Certificate expires in %d days", daysLeft),
		}, true
	default:
		return checks.Finding{}, false
	}
}

func isWeakRSAKey(algorithm string, strength, minBits int32) bool {
	return strings.EqualFold(algorithm, "RSA") && strength < minBits
}

func isSelfSigned(issuer, subject string) bool {
	return issuer != "" && issuer == subject
}

// hostnameCovered reports whether the domain is matched by any certificate SAN or
// DNS name, honouring single-label wildcard prefixes (*.example.com).
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
