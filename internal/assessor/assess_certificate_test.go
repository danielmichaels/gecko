package assessor

import (
	"context"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

func ts(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func findingByIssueType(
	findings []store.CertificateFindings,
	issueType string,
) (store.CertificateFindings, bool) {
	for _, f := range findings {
		if f.IssueType == issueType {
			return f, true
		}
	}
	return store.CertificateFindings{}, false
}

func TestAssessCertificate(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

	t.Run(
		"unhealthy cert yields expiry/weak-key/self-signed/mismatch findings",
		func(t *testing.T) {
			domain, err := pgContainer.Queries.DomainsGetByID(ctx, store.DomainsGetByIDParams{
				Uid:      "domain_00000001",
				TenantID: pgtype.Int4{Int32: 1, Valid: true},
			})
			if err != nil {
				t.Fatalf("Failed to get domain: %v", err)
			}

			_, err = pgContainer.Queries.ScannersStoreCertificate(
				ctx,
				store.ScannersStoreCertificateParams{
					DomainID:     pgtype.Int4{Int32: domain.ID, Valid: true},
					NotBefore:    ts(time.Now().Add(-2 * 365 * 24 * time.Hour)),
					NotAfter:     ts(time.Now().Add(-24 * time.Hour)), // expired yesterday
					Issuer:       "internal-ca.example",
					Subject:      "internal-ca.example", // issuer == subject -> self-signed
					KeyAlgorithm: "RSA",
					KeyStrength:  1024, // weak
					Sans:         []string{"other.example"},
					DnsNames:     []string{"other.example"}, // does not cover danielms.site
					CipherSuite:  "TLS_AES_128_GCM_SHA256",
					TlsVersion:   "1.2",
				},
			)
			if err != nil {
				t.Fatalf("Failed to store certificate: %v", err)
			}

			ident := observer.DomainIdentity{
				TenantID:   1,
				DomainID:   domain.ID,
				DomainUID:  domain.Uid,
				DomainName: domain.Name,
			}
			a := NewAssessor(
				Config{Store: pgContainer.Queries, Logger: testhelpers.TestLogger, Identity: ident},
			)
			if err := a.AssessCertificate(ctx, domain.Uid); err != nil {
				t.Fatalf("AssessCertificate failed: %v", err)
			}

			findings, err := pgContainer.Queries.AssessGetCertificateFindingsByDomainUID(
				ctx,
				store.AssessGetCertificateFindingsByDomainUIDParams{
					Uid:      domain.Uid,
					TenantID: pgtype.Int4{Int32: 1, Valid: true},
				},
			)
			if err != nil {
				t.Fatalf("Failed to get certificate findings: %v", err)
			}

			cases := []struct {
				issueType string
				severity  store.FindingSeverity
				status    store.FindingStatus
			}{
				{CertExpiry, store.FindingSeverityCritical, store.FindingStatusOpen},
				{CertWeakKey, store.FindingSeverityHigh, store.FindingStatusOpen},
				{CertSelfSigned, store.FindingSeverityMedium, store.FindingStatusOpen},
				{CertHostnameMismatch, store.FindingSeverityHigh, store.FindingStatusOpen},
			}
			for _, c := range cases {
				f, ok := findingByIssueType(findings, c.issueType)
				if !ok {
					t.Errorf("expected finding %q to be present", c.issueType)
					continue
				}
				if f.Severity != c.severity {
					t.Errorf(
						"%s: expected severity %s, got %s",
						c.issueType,
						c.severity,
						f.Severity,
					)
				}
				if f.Status != c.status {
					t.Errorf("%s: expected status %s, got %s", c.issueType, c.status, f.Status)
				}
			}
		},
	)

	t.Run("healthy cert yields compliant expiry and no problem findings", func(t *testing.T) {
		domain, err := pgContainer.Queries.DomainsGetByID(ctx, store.DomainsGetByIDParams{
			Uid:      "domain_00000002",
			TenantID: pgtype.Int4{Int32: 2, Valid: true},
		})
		if err != nil {
			t.Fatalf("Failed to get domain: %v", err)
		}

		_, err = pgContainer.Queries.ScannersStoreCertificate(
			ctx,
			store.ScannersStoreCertificateParams{
				DomainID:     pgtype.Int4{Int32: domain.ID, Valid: true},
				NotBefore:    ts(time.Now().Add(-24 * time.Hour)),
				NotAfter:     ts(time.Now().Add(365 * 24 * time.Hour)), // healthy
				Issuer:       "Lets Encrypt",
				Subject:      domain.Name,
				KeyAlgorithm: "ECDSA",
				KeyStrength:  256,
				Sans:         []string{domain.Name},
				DnsNames:     []string{domain.Name},
				CipherSuite:  "TLS_AES_128_GCM_SHA256",
				TlsVersion:   "1.3",
			},
		)
		if err != nil {
			t.Fatalf("Failed to store certificate: %v", err)
		}

		ident := observer.DomainIdentity{
			TenantID:   2,
			DomainID:   domain.ID,
			DomainUID:  domain.Uid,
			DomainName: domain.Name,
		}
		a := NewAssessor(
			Config{Store: pgContainer.Queries, Logger: testhelpers.TestLogger, Identity: ident},
		)
		if err := a.AssessCertificate(ctx, domain.Uid); err != nil {
			t.Fatalf("AssessCertificate failed: %v", err)
		}

		findings, err := pgContainer.Queries.AssessGetCertificateFindingsByDomainUID(
			ctx,
			store.AssessGetCertificateFindingsByDomainUIDParams{
				Uid:      domain.Uid,
				TenantID: pgtype.Int4{Int32: 2, Valid: true},
			},
		)
		if err != nil {
			t.Fatalf("Failed to get certificate findings: %v", err)
		}

		expiry, ok := findingByIssueType(findings, CertExpiry)
		if !ok {
			t.Fatalf("expected an expiry finding even for healthy cert")
		}
		if expiry.Severity != store.FindingSeverityInfo {
			t.Errorf("expected healthy expiry severity info, got %s", expiry.Severity)
		}
		if expiry.Status != store.FindingStatusCompliant {
			t.Errorf("expected healthy expiry status compliant, got %s", expiry.Status)
		}
		for _, it := range []string{CertWeakKey, CertSelfSigned, CertHostnameMismatch} {
			if _, present := findingByIssueType(findings, it); present {
				t.Errorf("did not expect finding %q for a healthy cert", it)
			}
		}
	})
}
