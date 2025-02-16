package scanner

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
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

func ScanCertificate(domain string) *CertificateResult {
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
	return &CertificateResult{
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
