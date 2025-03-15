package assessor

import (
	"context"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
	"log/slog"
	"os"
	"testing"
)

func TestAssessZoneTransfer_SPFIssues(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

	// Get a domain from the test data
	domain, err := pgContainer.Queries.DomainsGetByID(ctx, "domain_00000001")
	if err != nil {
		t.Fatalf("Failed to get domains: %v", err)
	}

	// First, insert TXT records that we'll use in our tests
	txtRecordIDs := make([]int32, 0)

	// Insert test TXT records
	testRecords := []string{
		"v=spf1 include:_spf.google.com -all",
		"v=spf1 include:_spf.google.com ~all",
		"v=spf1 include:_spf.google.com ?all",
		"v=spf1 include:_spf.google.com",
		"v=spf1 -all",
		"v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com -all",
	}

	for _, record := range testRecords {
		// Insert a TXT record
		txtRecord, err := pgContainer.Queries.RecordsCreateTXT(ctx, store.RecordsCreateTXTParams{
			DomainID: pgtype.Int4{Int32: domain.ID, Valid: true},
			Value:    record,
		})
		if err != nil {
			t.Fatalf("Failed to insert TXT record: %v", err)
		}
		txtRecordIDs = append(txtRecordIDs, txtRecord.ID)
	}

	tests := []struct {
		name          string
		handlesEmail  bool
		txtRecordIdx  int // Index into txtRecordIDs
		wantSeverity  store.FindingSeverity
		wantStatus    store.FindingStatus
		wantIssueType string
	}{
		{
			name:          "valid SPF record",
			handlesEmail:  true,
			txtRecordIdx:  0, // v=spf1 include:_spf.google.com -all
			wantSeverity:  store.FindingSeverityInfo,
			wantStatus:    store.FindingStatusClosed,
			wantIssueType: SPFCompliant,
		},
		{
			name:          "soft fail policy",
			handlesEmail:  true,
			txtRecordIdx:  1, // v=spf1 include:_spf.google.com ~all
			wantSeverity:  store.FindingSeverityMedium,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: SPFSoftFailPolicy,
		},
		{
			name:          "weak policy",
			handlesEmail:  true,
			txtRecordIdx:  2, // v=spf1 include:_spf.google.com ?all
			wantSeverity:  store.FindingSeverityHigh,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: SPFWeakPolicy,
		},
		{
			name:          "missing all mechanism",
			handlesEmail:  true,
			txtRecordIdx:  3, // v=spf1 include:_spf.google.com
			wantSeverity:  store.FindingSeverityHigh,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: SPFMissingAllMechanism,
		},
		{
			name:          "missing mechanisms",
			handlesEmail:  true,
			txtRecordIdx:  4, // v=spf1 -all
			wantSeverity:  store.FindingSeverityMedium,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: SPFMissingMechanisms,
		},
		{
			name:          "excessive lookups",
			handlesEmail:  true,
			txtRecordIdx:  5, // v=spf1 include:a.com include:b.com ... -all
			wantSeverity:  store.FindingSeverityMedium,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: SPFExcessiveLookups,
		},
		{
			name:          "missing SPF record",
			handlesEmail:  true,
			txtRecordIdx:  1, // No SPF record
			wantSeverity:  store.FindingSeverityCritical,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: SPFMissing,
		},
		{
			name:          "domain doesn't handle email",
			handlesEmail:  false,
			txtRecordIdx:  1, // No SPF record
			wantSeverity:  store.FindingSeverityInfo,
			wantStatus:    store.FindingStatusNotApplicable,
			wantIssueType: NotApplicable,
		},
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	// Create assessor with the logger
	assessor := NewAssessor(Config{Store: pgContainer.Queries, Logger: logger})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var txtRecords []store.TxtRecords

			txtRecords, err := pgContainer.Queries.RecordsGetTXTByDomainID(ctx, pgtype.Int4{Int32: txtRecordIDs[tt.txtRecordIdx], Valid: true})
			if err != nil {
				t.Fatalf("Failed to get TXT record: %v", err)
			}

			data := assessData{
				handlesEmail: tt.handlesEmail,
				domainID:     int(domain.ID),
				txtRecords:   txtRecords,
			}

			err = assessor.assessSPF(ctx, data)
			if err != nil {
				t.Fatalf("assessSPF failed: %v", err)
			}

			findings, err := pgContainer.Queries.AssessGetSPFFindings(ctx, pgtype.Int4{Int32: domain.ID, Valid: true})
			if err != nil {
				t.Fatalf("Failed to get SPF findings: %v", err)
			}

			// Print all findings for debugging
			t.Logf("Found %d findings for test %s:", len(findings), tt.name)
			for i, f := range findings {
				t.Logf("  Finding %d: IssueType=%s, Severity=%s, Status=%s",
					i+1, f.IssueType, f.Severity, f.Status)
			}

			// Find the specific finding we're looking for
			var foundIssueType string
			var foundSeverity store.FindingSeverity
			var foundStatus store.FindingStatus

			for _, finding := range findings {
				if finding.IssueType == tt.wantIssueType {
					foundIssueType = finding.IssueType
					foundSeverity = finding.Severity
					foundStatus = finding.Status
					break
				}
			}

			// Use want/got approach for clearer error messages
			if got, want := foundIssueType, tt.wantIssueType; got != want {
				t.Errorf("IssueType: got=%s, want=%s", got, want)
			}

			if foundIssueType != "" {
				if got, want := foundSeverity, tt.wantSeverity; got != want {
					t.Errorf("Severity: got=%s, want=%s", got, want)
				}

				if got, want := foundStatus, tt.wantStatus; got != want {
					t.Errorf("Status: got=%s, want=%s", got, want)
				}
			}
		})
	}
}
