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

func caaConfigByIssueType(
	findings []store.CaaConfigurationFindings,
	issueType string,
) (store.CaaConfigurationFindings, bool) {
	for _, f := range findings {
		if f.IssueType == issueType {
			return f, true
		}
	}
	return store.CaaConfigurationFindings{}, false
}

func caaComplianceByIssueType(
	findings []store.CaaComplianceFindings,
	issueType string,
) (store.CaaComplianceFindings, bool) {
	for _, f := range findings {
		if f.IssueType == issueType {
			return f, true
		}
	}
	return store.CaaComplianceFindings{}, false
}

func TestAssessCAA(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

	newDomain := func(t *testing.T, name string) store.DomainsCreateRow {
		t.Helper()
		d, err := pgContainer.Queries.DomainsCreate(ctx, store.DomainsCreateParams{
			TenantID:   pgtype.Int4{Int32: 1, Valid: true},
			Name:       name,
			DomainType: store.DomainTypeTld,
			Source:     store.DomainSourceUserSupplied,
			Status:     store.DomainStatusActive,
		})
		if err != nil {
			t.Fatalf("Failed to create domain %s: %v", name, err)
		}
		return d
	}

	seedCAA := func(t *testing.T, domainID int32, flags int32, tag, value string) {
		t.Helper()
		if _, err := pgContainer.Queries.RecordsCreateCAA(ctx, store.RecordsCreateCAAParams{
			DomainID: pgtype.Int4{Int32: domainID, Valid: true},
			Flags:    flags,
			Tag:      tag,
			Value:    value,
		}); err != nil {
			t.Fatalf("Failed to seed CAA record: %v", err)
		}
	}

	seedCert := func(t *testing.T, domainID int32) {
		t.Helper()
		now := time.Now()
		if _, err := pgContainer.Queries.ScannersStoreCertificate(ctx, store.ScannersStoreCertificateParams{
			DomainID:      pgtype.Int4{Int32: domainID, Valid: true},
			NotBefore:     pgtype.Timestamptz{Time: now.Add(-24 * time.Hour), Valid: true},
			NotAfter:      pgtype.Timestamptz{Time: now.Add(60 * 24 * time.Hour), Valid: true},
			Issuer:        "CN=R3,O=Let's Encrypt,C=US",
			Subject:       "CN=example.test",
			KeyAlgorithm:  "ECDSA",
			KeyStrength:   256,
			Sans:          []string{},
			DnsNames:      []string{},
			IssuerCertUrl: []string{},
			CipherSuite:   "TLS_AES_128_GCM_SHA256",
			TlsVersion:    "TLS 1.3",
		}); err != nil {
			t.Fatalf("Failed to seed certificate: %v", err)
		}
	}

	run := func(t *testing.T, d store.DomainsCreateRow) {
		t.Helper()
		ident := observer.DomainIdentity{
			TenantID:   1,
			DomainID:   d.ID,
			DomainUID:  d.Uid,
			DomainName: d.Name,
		}
		a := NewAssessor(
			Config{Store: pgContainer.Queries, Logger: testhelpers.TestLogger, Identity: ident},
		)
		if err := a.AssessCAA(ctx, d.Uid); err != nil {
			t.Fatalf("AssessCAA failed: %v", err)
		}
	}

	getConfig := func(t *testing.T, d store.DomainsCreateRow) []store.CaaConfigurationFindings {
		t.Helper()
		findings, err := pgContainer.Queries.AssessGetCAAConfigurationFindingsByDomainUID(
			ctx,
			store.AssessGetCAAConfigurationFindingsByDomainUIDParams{
				Uid:      d.Uid,
				TenantID: pgtype.Int4{Int32: 1, Valid: true},
			},
		)
		if err != nil {
			t.Fatalf("Failed to get CAA configuration findings: %v", err)
		}
		return findings
	}

	getCompliance := func(t *testing.T, d store.DomainsCreateRow) []store.CaaComplianceFindings {
		t.Helper()
		findings, err := pgContainer.Queries.AssessGetCAAComplianceFindingsByDomainUID(
			ctx,
			store.AssessGetCAAComplianceFindingsByDomainUIDParams{
				Uid:      d.Uid,
				TenantID: pgtype.Int4{Int32: 1, Valid: true},
			},
		)
		if err != nil {
			t.Fatalf("Failed to get CAA compliance findings: %v", err)
		}
		return findings
	}

	t.Run("no CAA and no cert is an informational missing finding", func(t *testing.T) {
		d := newDomain(t, "no-caa-no-cert.test")
		run(t, d)

		f, ok := caaConfigByIssueType(getConfig(t, d), CAAMissing)
		if !ok {
			t.Fatalf("expected caa_missing finding")
		}
		if f.Severity != store.FindingSeverityInfo {
			t.Errorf("expected info severity, got %s", f.Severity)
		}
		if f.Status != store.FindingStatusOpen {
			t.Errorf("expected open status, got %s", f.Status)
		}
		if _, present := caaComplianceByIssueType(getCompliance(t, d), CAARequiredForCert); present {
			t.Error("did not expect a cert-compliance finding without a certificate")
		}
	})

	t.Run("no CAA with a certificate escalates and adds a compliance finding", func(t *testing.T) {
		d := newDomain(t, "no-caa-with-cert.test")
		seedCert(t, d.ID)
		run(t, d)

		cfg, ok := caaConfigByIssueType(getConfig(t, d), CAAMissing)
		if !ok {
			t.Fatalf("expected caa_missing finding")
		}
		if cfg.Severity != store.FindingSeverityLow {
			t.Errorf("expected low severity when cert present, got %s", cfg.Severity)
		}
		if cfg.Status != store.FindingStatusOpen {
			t.Errorf("expected open status, got %s", cfg.Status)
		}

		comp, ok := caaComplianceByIssueType(getCompliance(t, d), CAARequiredForCert)
		if !ok {
			t.Fatalf("expected caa_required_for_cert compliance finding")
		}
		if comp.Severity != store.FindingSeverityLow || comp.Status != store.FindingStatusOpen {
			t.Errorf("expected low/open, got %s/%s", comp.Severity, comp.Status)
		}
		if !comp.StandardName.Valid || comp.StandardName.String == "" {
			t.Error("expected standard_name to be set on the compliance finding")
		}
	})

	t.Run("restrictive CAA with trusted issuer and iodef has no open findings", func(t *testing.T) {
		d := newDomain(t, "good-caa.test")
		seedCAA(t, d.ID, 0, "issue", "letsencrypt.org")
		seedCAA(t, d.ID, 0, "iodef", "mailto:security@good-caa.test")
		run(t, d)

		for _, f := range getConfig(t, d) {
			if f.Status == store.FindingStatusOpen {
				t.Errorf("unexpected open config finding %s", f.IssueType)
			}
		}
		for _, f := range getCompliance(t, d) {
			if f.Status == store.FindingStatusOpen {
				t.Errorf("unexpected open compliance finding %s", f.IssueType)
			}
		}
		if missing, ok := caaConfigByIssueType(getConfig(t, d), CAAMissing); ok {
			if missing.Status != store.FindingStatusResolved {
				t.Errorf("expected caa_missing resolved, got %s", missing.Status)
			}
		}
	})

	t.Run("CAA without an issue tag permits any CA", func(t *testing.T) {
		d := newDomain(t, "any-ca.test")
		seedCAA(t, d.ID, 0, "iodef", "mailto:security@any-ca.test")
		run(t, d)

		f, ok := caaConfigByIssueType(getConfig(t, d), CAAAllowsAnyCA)
		if !ok {
			t.Fatalf("expected caa_allows_any_ca finding")
		}
		if f.Severity != store.FindingSeverityLow || f.Status != store.FindingStatusOpen {
			t.Errorf("expected low/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("issuer outside the allowlist is flagged as untrusted", func(t *testing.T) {
		d := newDomain(t, "untrusted-ca.test")
		seedCAA(t, d.ID, 0, "issue", "sketchy-ca.example")
		run(t, d)

		f, ok := caaConfigByIssueType(getConfig(t, d), CAAUntrustedIssuer)
		if !ok {
			t.Fatalf("expected caa_untrusted_issuer finding")
		}
		if f.Severity != store.FindingSeverityLow || f.Status != store.FindingStatusOpen {
			t.Errorf("expected low/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("critical flag on an unknown tag is a medium finding", func(t *testing.T) {
		d := newDomain(t, "unknown-critical.test")
		seedCAA(t, d.ID, 0, "issue", "letsencrypt.org")
		seedCAA(t, d.ID, 128, "futuretag", "anything")
		run(t, d)

		f, ok := caaConfigByIssueType(getConfig(t, d), CAAUnknownCriticalFlag)
		if !ok {
			t.Fatalf("expected caa_unknown_critical_flag finding")
		}
		if f.Severity != store.FindingSeverityMedium || f.Status != store.FindingStatusOpen {
			t.Errorf("expected medium/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("no-issuance directive alongside a permitted CA is conflicting", func(t *testing.T) {
		d := newDomain(t, "conflicting-caa.test")
		seedCAA(t, d.ID, 0, "issue", ";")
		seedCAA(t, d.ID, 0, "issue", "letsencrypt.org")
		run(t, d)

		f, ok := caaConfigByIssueType(getConfig(t, d), CAAConflictingRecords)
		if !ok {
			t.Fatalf("expected caa_conflicting_records finding")
		}
		if f.Severity != store.FindingSeverityMedium || f.Status != store.FindingStatusOpen {
			t.Errorf("expected medium/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("CAA without iodef is an informational compliance gap", func(t *testing.T) {
		d := newDomain(t, "no-iodef.test")
		seedCAA(t, d.ID, 0, "issue", "digicert.com")
		run(t, d)

		f, ok := caaComplianceByIssueType(getCompliance(t, d), CAAMissingIodef)
		if !ok {
			t.Fatalf("expected missing_iodef compliance finding")
		}
		if f.Severity != store.FindingSeverityInfo || f.Status != store.FindingStatusOpen {
			t.Errorf("expected info/open, got %s/%s", f.Severity, f.Status)
		}
	})

	t.Run("re-running does not duplicate findings", func(t *testing.T) {
		d := newDomain(t, "idempotent-caa.test")
		run(t, d)
		run(t, d)

		var count int
		for _, f := range getConfig(t, d) {
			if f.IssueType == CAAMissing {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected exactly one caa_missing finding after re-run, got %d", count)
		}
	})
}
