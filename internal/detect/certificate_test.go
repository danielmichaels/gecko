package detect

import (
	"sort"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/checks"
)

func certDetector() CertificateDetector {
	return CertificateDetector{ExpiryHighDays: 14, ExpiryMediumDays: 30, MinRSAKeyBits: 2048}
}

// healthyCert is a fully-compliant baseline each case mutates one field of.
func healthyCert(now time.Time) CertificateEvidence {
	return CertificateEvidence{
		ObservedAt:   now,
		DomainName:   "example.com",
		Fetched:      true,
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyAlgorithm: "RSA",
		KeyStrength:  4096,
		Issuer:       "DigiCert Global CA",
		Subject:      "example.com",
		SANs:         []string{"example.com", "www.example.com"},
		DNSNames:     []string{"example.com"},
	}
}

func TestCertificateDetect(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	d := certDetector()

	tests := []struct {
		name       string
		mutate     func(*CertificateEvidence)
		wantIssues []string
		wantSev    map[string]string // issue_type -> severity, checked when set
	}{
		{
			name:       "healthy cert yields no findings",
			mutate:     func(*CertificateEvidence) {},
			wantIssues: nil,
		},
		{
			name:       "expired cert is critical",
			mutate:     func(e *CertificateEvidence) { e.NotAfter = now.Add(-24 * time.Hour) },
			wantIssues: []string{IssueCertExpiry},
			wantSev:    map[string]string{IssueCertExpiry: "critical"},
		},
		{
			name:       "expiry inside high window is high",
			mutate:     func(e *CertificateEvidence) { e.NotAfter = now.Add(10 * 24 * time.Hour) },
			wantIssues: []string{IssueCertExpiry},
			wantSev:    map[string]string{IssueCertExpiry: "high"},
		},
		{
			name:       "expiry inside medium window is medium",
			mutate:     func(e *CertificateEvidence) { e.NotAfter = now.Add(20 * 24 * time.Hour) },
			wantIssues: []string{IssueCertExpiry},
			wantSev:    map[string]string{IssueCertExpiry: "medium"},
		},
		{
			name:       "expiry beyond medium window is compliant (absence)",
			mutate:     func(e *CertificateEvidence) { e.NotAfter = now.Add(60 * 24 * time.Hour) },
			wantIssues: nil,
		},
		{
			name:       "weak RSA key",
			mutate:     func(e *CertificateEvidence) { e.KeyStrength = 1024 },
			wantIssues: []string{IssueCertWeakKey},
		},
		{
			name: "strong non-RSA key is fine",
			mutate: func(e *CertificateEvidence) {
				e.KeyAlgorithm = "ECDSA"
				e.KeyStrength = 256
			},
			wantIssues: nil,
		},
		{
			name:       "self-signed",
			mutate:     func(e *CertificateEvidence) { e.Issuer = "example.com" },
			wantIssues: []string{IssueCertSelfSigned},
		},
		{
			name: "hostname mismatch",
			mutate: func(e *CertificateEvidence) {
				e.SANs = []string{"other.com"}
				e.DNSNames = []string{"other.com"}
			},
			wantIssues: []string{IssueCertHostnameMismatch},
		},
		{
			name: "wildcard SAN covers single label",
			mutate: func(e *CertificateEvidence) {
				e.DomainName = "www.example.com"
				e.SANs = []string{"*.example.com"}
				e.DNSNames = nil
			},
			wantIssues: nil,
		},
		{
			name:       "no certificate fetched yields nothing (unknown != fine)",
			mutate:     func(e *CertificateEvidence) { *e = CertificateEvidence{Fetched: false} },
			wantIssues: nil,
		},
		{
			name: "multiple problems compound",
			mutate: func(e *CertificateEvidence) {
				e.NotAfter = now.Add(-time.Hour)
				e.KeyStrength = 512
				e.Issuer = "example.com"
			},
			wantIssues: []string{IssueCertExpiry, IssueCertSelfSigned, IssueCertWeakKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := healthyCert(now)
			tt.mutate(&ev)
			detRes, err := d.Detect(ev)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			got := detRes.Found

			gotIssues := make([]string, len(got))
			sevByIssue := map[string]string{}
			for i, f := range got {
				gotIssues[i] = f.IssueType
				sevByIssue[f.IssueType] = f.Severity
			}
			sort.Strings(gotIssues)
			want := append([]string(nil), tt.wantIssues...)
			sort.Strings(want)

			if !equalStrings(gotIssues, want) {
				t.Fatalf("issues = %v, want %v", gotIssues, want)
			}
			for it, sev := range tt.wantSev {
				if sevByIssue[it] != sev {
					t.Errorf("severity[%s] = %q, want %q", it, sevByIssue[it], sev)
				}
			}
		})
	}
}

// findingsOf returns just the Found slice of a Detect result, for tests that
// assert only on findings. The detectors here never return an error.
func findingsOf(res checks.DetectResult, _ error) []checks.Finding { return res.Found }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
