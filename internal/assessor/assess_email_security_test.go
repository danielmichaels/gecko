package assessor

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
)

func TestAssessEmailSecurity_SPFIssues(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

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
	// Create assessor with the logger
	assessor := NewAssessor(Config{Store: pgContainer.Queries, Logger: testhelpers.TestLogger})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var txtRecords []store.TxtRecords

			txtRecords, err := pgContainer.Queries.RecordsGetTXTByDomainID(
				ctx,
				pgtype.Int4{Int32: txtRecordIDs[tt.txtRecordIdx], Valid: true},
			)
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

			findings, err := pgContainer.Queries.AssessGetSPFFindings(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
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

func TestAssessEmailSecurity_DKIM(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

	// Create a mock DNS server
	mockServer, err := testhelpers.NewMockDNSServer()
	if err != nil {
		t.Fatalf("Failed to create mock DNS server: %v", err)
	}
	if err := mockServer.Start(); err != nil {
		t.Fatalf("Failed to start mock DNS server: %v", err)
	}
	defer func(mockServer *testhelpers.MockDNSServer) {
		err := mockServer.Stop()
		if err != nil {
			t.Fatalf("Failed to stop mock DNS server: %v", err)
		}
	}(mockServer)

	domain, err := pgContainer.Queries.DomainsGetByID(ctx, "domain_00000001")
	if err != nil {
		t.Fatalf("Failed to get domains: %v", err)
	}
	// Create a DNS client that uses our mock server
	dnsClient := dnsclient.New(
		dnsclient.WithServers([]string{mockServer.ListenAddr}),
		dnsclient.WithLogger(testhelpers.TestLogger),
	)

	assessor := NewAssessor(Config{
		Store:     pgContainer.Queries,
		Logger:    testhelpers.TestLogger,
		DNSClient: dnsClient,
	})

	tests := []struct {
		name          string
		handlesEmail  bool
		dkimRecords   map[string][]string // Map of selector to DKIM records
		selectors     []string
		wantSeverity  store.FindingSeverity
		wantStatus    store.FindingStatus
		wantIssueType string
		wantSelector  string
	}{
		{
			name:         "valid DKIM record",
			handlesEmail: true,
			dkimRecords: map[string][]string{
				"selector1": {
					"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5oIUrFDn1OuSWCmZ8Ac8IgLaoFR64YP+zRERlH7XiANVAJQGgwIexnbZ1xNDt+1DgXWfSALZnTcXLwX7tJP8wZBzpwrKXJjxPMXIAXCNXNzo/fe8CnWKjnPSxUVLW/QYa4AlNzL/DS8QEJKfqSxZTN5kT7VWvuXsj+8wPnGdFKrwOxkgDqzFASIyjON3JOCWPfhEYzGdnQl3z0Njx7cVpzQzSaQkySVBJZUkGYbpT0UQbPQni7TFbtsWNgZ9nA2ZUJe0D/xhAsepHhRi6KCaNFmh/FgA0jV/xuxsBY/RQUbrHUfV/nDr8aLI+Sh2IaXaIh+FFAPGY6TJJbRkwIDAQAB",
				},
			},
			selectors:     []string{"selector1"},
			wantSeverity:  store.FindingSeverityInfo,
			wantStatus:    store.FindingStatusClosed,
			wantIssueType: DKIMCompliant,
			wantSelector:  "selector1",
		},
		{
			name:         "weak key length",
			handlesEmail: true,
			dkimRecords: map[string][]string{
				"selector1": {
					"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5wi9P", // Short key
				},
			},
			selectors:     []string{"selector1"},
			wantSeverity:  store.FindingSeverityHigh,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: DKIMWeakKeyLength,
			wantSelector:  "selector1",
		},
		{
			name:         "test mode enabled",
			handlesEmail: true,
			dkimRecords: map[string][]string{
				"selector1": {
					"v=DKIM1; k=rsa; t=y; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5oIUrFDn1OuSWCmZ8Ac8IgLaoFR64YP+zRERlH7XiANVAJQGgwIexnbZ1xNDt+1DgXWfSALZnTcXLwX7tJP8wZBzpwrKXJjxPMXIAXCNXNzo/fe8CnWKjnPSxUVLW/QYa4AlNzL/DS8QEJKfqSxZTN5kT7VWvuXsj+8wPnGdFKrwOxkgDqzFASIyjON3JOCWPfhEYzGdnQl3z0Njx7cVpzQzSaQkySVBJZUkGYbpT0UQbPQni7TFbtsWNgZ9nA2ZUJe0D/xhAsepHhRi6KCaNFmh/FgA0jV/xuxsBY/RQUbrHUfV/nDr8aLI+Sh2IaXaIh+FFAPGY6TJJbRkwIDAQAB",
				},
			},
			selectors:     []string{"selector1"},
			wantSeverity:  store.FindingSeverityMedium,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: DKIMTestModeEnabled,
			wantSelector:  "selector1",
		},
		{
			name:          "missing DKIM record",
			handlesEmail:  true,
			dkimRecords:   map[string][]string{}, // No DKIM records
			selectors:     []string{"selector1"},
			wantSeverity:  store.FindingSeverityHigh,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: DKIMMissing,
			wantSelector:  "",
		},
		{
			name:          "domain doesn't handle email",
			handlesEmail:  false,
			dkimRecords:   map[string][]string{}, // No DKIM records
			selectors:     []string{"selector1"},
			wantSeverity:  store.FindingSeverityInfo,
			wantStatus:    store.FindingStatusNotApplicable,
			wantIssueType: NotApplicable,
			wantSelector:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				_, err := pgContainer.Pool.Exec(
					ctx,
					"DELETE FROM dkim_findings WHERE domain_id = $1",
					domain.ID,
				)
				if err != nil {
					t.Fatalf("Failed to clear previous findings: %v", err)
				}
				mockServer.ClearRecords()
			})

			// Add SPF record to indicate the domain handles email
			if tt.handlesEmail {
				err = mockServer.AddRecord(
					domain.Name,
					dns.TypeTXT,
					3600,
					"v=spf1 include:_spf.google.com -all",
				)
				if err != nil {
					t.Fatalf("Failed to add SPF record: %v", err)
				}
			}

			// Add DKIM records to the mock server
			for selector, records := range tt.dkimRecords {
				dkimDomain := selector + "._domainkey." + domain.Name
				// Ensure we add all records provided for a selector (though usually it's one)
				for _, record := range records {
					err = mockServer.AddRecord(dkimDomain, dns.TypeTXT, 3600, record)
					if err != nil {
						t.Fatalf("Failed to add DKIM record for %s: %v", dkimDomain, err)
					}
				}
			}

			// Create assessData with the test data
			data := assessData{
				handlesEmail: tt.handlesEmail,
				domainID:     int(domain.ID),
				txtRecords:   []store.TxtRecords{}, // Not used by assessDKIM
			}

			err = assessor.assessDKIM(ctx, data, tt.selectors)
			if err != nil {
				t.Fatalf("assessDKIM failed: %v", err)
			}

			// Get the findings from the database
			findings, err := pgContainer.Queries.AssessGetDKIMFindings(
				ctx,
				pgtype.Int4{Int32: domain.ID, Valid: true},
			)
			if err != nil {
				t.Fatalf("Failed to get DKIM findings: %v", err)
			}

			// Print all findings for debugging
			t.Logf("Found %d findings for test %s:", len(findings), tt.name)
			for i, f := range findings {
				t.Logf("  Finding %d: IssueType=%s, Severity=%s, Status=%s, Selector=%s",
					i+1, f.IssueType, f.Severity, f.Status, f.Selector.String)
			}

			// Find the specific finding we're looking for
			var foundIssueType string
			var foundSeverity store.FindingSeverity
			var foundStatus store.FindingStatus
			var foundSelector string

			for _, finding := range findings {
				if finding.IssueType == tt.wantIssueType {
					foundIssueType = finding.IssueType
					foundSeverity = finding.Severity
					foundStatus = finding.Status
					foundSelector = finding.Selector.String
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

				if got, want := foundSelector, tt.wantSelector; got != want &&
					tt.wantSelector != "" {
					t.Errorf("Selector: got=%s, want=%s", got, want)
				}
			}
		})
	}
}

func TestAssessEmailSecurity_DMARC(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

	// Create a mock DNS server
	mockServer, err := testhelpers.NewMockDNSServer()
	if err != nil {
		t.Fatalf("Failed to create mock DNS server: %v", err)
	}
	if err := mockServer.Start(); err != nil {
		t.Fatalf("Failed to start mock DNS server: %v", err)
	}
	defer func(mockServer *testhelpers.MockDNSServer) {
		err := mockServer.Stop()
		if err != nil {
			t.Fatalf("Failed to stop mock DNS server: %v", err)
		}
	}(mockServer)

	domain, err := pgContainer.Queries.DomainsGetByID(ctx, "domain_00000001")
	if err != nil {
		t.Fatalf("Failed to get domains: %v", err)
	}

	// Create a DNS client that uses our mock server
	dnsClient := dnsclient.New(
		dnsclient.WithServers([]string{mockServer.ListenAddr}),
		dnsclient.WithLogger(testhelpers.TestLogger),
	)

	assessor := NewAssessor(Config{
		Store:     pgContainer.Queries,
		Logger:    testhelpers.TestLogger,
		DNSClient: dnsClient,
	})

	tests := []struct {
		name          string
		handlesEmail  bool
		dmarcRecords  []string
		wantSeverity  store.FindingSeverity
		wantStatus    store.FindingStatus
		wantIssueType string
		wantPolicy    string
	}{
		{
			name:         "valid DMARC record",
			handlesEmail: true,
			dmarcRecords: []string{
				"v=DMARC1; p=reject; rua=mailto:reports@example.com; ruf=mailto:forensic@example.com",
			},
			wantSeverity:  store.FindingSeverityInfo,
			wantStatus:    store.FindingStatusClosed,
			wantIssueType: DMARCCompliant,
			wantPolicy:    "v=DMARC1; p=reject; rua=mailto:reports@example.com; ruf=mailto:forensic@example.com",
		},
		{
			name:         "weak policy",
			handlesEmail: true,
			dmarcRecords: []string{
				"v=DMARC1; p=none; rua=mailto:reports@example.com; ruf=mailto:forensic@example.com",
			},
			wantSeverity:  store.FindingSeverityHigh,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: DMARCWeakPolicy,
			wantPolicy:    "v=DMARC1; p=none; rua=mailto:reports@example.com; ruf=mailto:forensic@example.com",
		},
		{
			name:          "missing tags",
			handlesEmail:  true,
			dmarcRecords:  []string{"v=DMARC1; p=reject"},
			wantSeverity:  store.FindingSeverityInfo,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: DMARCMissingTags,
			wantPolicy:    "v=DMARC1; p=reject",
		},
		{
			name:          "weak policy and missing tags",
			handlesEmail:  true,
			dmarcRecords:  []string{"v=DMARC1; p=none"},
			wantSeverity:  store.FindingSeverityHigh,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: DMARCWeakPolicy,
			wantPolicy:    "v=DMARC1; p=none",
		},
		{
			name:          "missing DMARC record",
			handlesEmail:  true,
			dmarcRecords:  []string{},
			wantSeverity:  store.FindingSeverityCritical,
			wantStatus:    store.FindingStatusOpen,
			wantIssueType: DMARCMissing,
			wantPolicy:    "",
		},
		{
			name:          "domain doesn't handle email",
			handlesEmail:  false,
			dmarcRecords:  []string{},
			wantSeverity:  store.FindingSeverityInfo,
			wantStatus:    store.FindingStatusNotApplicable,
			wantIssueType: NotApplicable,
			wantPolicy:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				_, err := pgContainer.Pool.Exec(
					ctx,
					"DELETE FROM dmarc_findings WHERE domain_id = $1",
					domain.ID,
				)
				if err != nil {
					t.Fatalf("Failed to clear previous findings: %v", err)
				}
				mockServer.ClearRecords()
			})

			// Add SPF record to indicate the domain handles email
			if tt.handlesEmail {
				err = mockServer.AddRecord(domain.Name, dns.TypeMX, 3600, "10 mail.example.com.")
				if err != nil {
					t.Fatalf("Failed to add MX record: %v", err)
				}
			}

			// Add DMARC records to the mock server
			dmarcDomain := "_dmarc." + domain.Name
			for _, record := range tt.dmarcRecords {
				err = mockServer.AddRecord(dmarcDomain, dns.TypeTXT, 3600, record)
				if err != nil {
					t.Fatalf("Failed to add DMARC record: %v", err)
				}
			}

			// Create assessData with the test data
			data := assessData{
				handlesEmail: tt.handlesEmail,
				domainID:     int(domain.ID),
				txtRecords:   []store.TxtRecords{}, // Not used by assessDMARC
			}

			err = assessor.assessDMARC(ctx, data)
			if err != nil {
				t.Fatalf("assessDMARC failed: %v", err)
			}

			// Get the findings from the database
			findings, err := pgContainer.Queries.AssessGetDMARCFindingsByDomainID(ctx, domain.Uid)
			if err != nil {
				t.Fatalf("Failed to get DMARC findings: %v", err)
			}

			// Print all findings for debugging
			t.Logf("Found %d findings for test %s:", len(findings), tt.name)
			for i, f := range findings {
				t.Logf("  Finding %d: IssueType=%s, Severity=%s, Status=%s, Policy=%s",
					i+1, f.IssueType, f.Severity, f.Status, f.Policy.String)
			}

			// Find the specific finding we're looking for
			var foundIssueType string
			var foundSeverity store.FindingSeverity
			var foundStatus store.FindingStatus
			var foundPolicy string

			for _, finding := range findings {
				if finding.IssueType == tt.wantIssueType {
					foundIssueType = finding.IssueType
					foundSeverity = finding.Severity
					foundStatus = finding.Status
					foundPolicy = finding.Policy.String
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

				if got, want := foundPolicy, tt.wantPolicy; got != want && tt.wantPolicy != "" {
					t.Errorf("Policy: got=%s, want=%s", got, want)
				}
			}
		})
	}
}
