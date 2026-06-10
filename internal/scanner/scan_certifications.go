package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

type CertificateResult struct {
	NotBefore     time.Time
	NotAfter      time.Time
	Issuer        string
	IssuerOrgName string
	IssuerCountry string
	Subject       string
	KeyAlgorithm  string
	CipherSuite   string
	TLSVersion    string
	SANs          []string
	DNSNames      []string
	IssuerCertURL []string
	KeyStrength   int
	IsCA          bool
}

func (s *Scan) ScanCertificate(ctx context.Context, domain string) *CertificateResult {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	dialer := &net.Dialer{
		// todo: make configurable
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", domain), conf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	var orgName, country string
	if len(cert.Issuer.Organization) > 0 {
		orgName = cert.Issuer.Organization[0]
	}
	if len(cert.Issuer.Country) > 0 {
		country = cert.Issuer.Country[0]
	}
	result := &CertificateResult{
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		Issuer:        cert.Issuer.CommonName,
		IssuerOrgName: orgName,
		IssuerCountry: country,
		Subject:       cert.Subject.CommonName,
		KeyAlgorithm:  cert.PublicKeyAlgorithm.String(),
		KeyStrength:   getKeyStrength(cert),
		SANs:          cert.DNSNames,
		DNSNames:      cert.DNSNames,
		IsCA:          cert.IsCA,
		IssuerCertURL: cert.IssuingCertificateURL,
		CipherSuite:   tls.CipherSuiteName(conn.ConnectionState().CipherSuite),
		TLSVersion:    getTLSVersion(conn.ConnectionState().Version),
	}

	s.storeCertificate(ctx, result)
	return result
}

// storeCertificate upserts the certificate scan result into the live projection
// table and emits its observation. It is a no-op without a real scan identity
// (zero DomainID in unit tests).
func (s *Scan) storeCertificate(ctx context.Context, result *CertificateResult) {
	if s.identity.DomainID == 0 || s.store == nil {
		return
	}
	_, err := s.store.ScannersStoreCertificate(ctx, store.ScannersStoreCertificateParams{
		DomainID:      pgtype.Int4{Int32: s.identity.DomainID, Valid: true},
		NotBefore:     pgtype.Timestamptz{Time: result.NotBefore, Valid: true},
		NotAfter:      pgtype.Timestamptz{Time: result.NotAfter, Valid: true},
		Issuer:        result.Issuer,
		IssuerOrgName: pgtype.Text{String: result.IssuerOrgName, Valid: result.IssuerOrgName != ""},
		IssuerCountry: pgtype.Text{String: result.IssuerCountry, Valid: result.IssuerCountry != ""},
		Subject:       result.Subject,
		KeyAlgorithm:  result.KeyAlgorithm,
		KeyStrength:   int32(result.KeyStrength),
		Sans:          nonNil(result.SANs),
		DnsNames:      nonNil(result.DNSNames),
		IsCa:          result.IsCA,
		IssuerCertUrl: nonNil(result.IssuerCertURL),
		CipherSuite:   result.CipherSuite,
		TlsVersion:    result.TLSVersion,
	})
	if err != nil {
		s.logger.Error("failed to store certificate", "error", err)
		return
	}

	payload := observer.PayloadJSON(map[string]any{
		"issuer":        result.Issuer,
		"subject":       result.Subject,
		"not_after":     result.NotAfter.UTC().Format(time.RFC3339),
		"key_algorithm": result.KeyAlgorithm,
		"key_strength":  result.KeyStrength,
		"tls_version":   result.TLSVersion,
	})
	if err := observer.New(s.store).RecordFindingChange(
		ctx, s.identity, observer.EntityCertificate, "certificate", payload,
	); err != nil {
		s.logger.Error("failed to emit certificate observation", "error", err)
	}
}

// nonNil returns an empty slice for a nil input so NOT NULL array columns never
// receive a NULL.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func getKeyStrength(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	default:
		return 0
	}
}

func getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "unknown"
	}
}
