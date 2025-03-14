package assessor

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/sync/errgroup"
)

const (
	// MinDKIMKeyLength is the minimum allowed DKIM key length
	MinDKIMKeyLength = 270
	// MaxSPFLookups is the maximum allowed SPF include mechanisms
	MaxSPFLookups = 10
	// BIMIPrefix is the prefix for BIMI records todo
	BIMIPrefix = "v=BIMI1;"

	// NotApplicable is a placeholder for not applicable values for any assessor
	NotApplicable = "not_applicable"

	FindingDKIM  = "DKIM"
	FindingDMARC = "DMARC"
	FindingSPF   = "SPF"

	SPFCompliant           = "spf_compliant"
	SPFWeakPolicy          = "weak_spf_policy"
	SPFSoftFailPolicy      = "soft_fail_spf_policy"
	SPFMissingMechanisms   = "missing_mechanisms"
	SPFMissingAllMechanism = "missing_all_mechanism"
	SPFExcessiveLookups    = "excessive_lookups"
	SPFMissing             = "missing_spf"

	DKIMCompliant       = "dkim_compliant"
	DKIMWeakKeyLength   = "weak_key_length"
	DKIMMissingTags     = "missing_tags"
	DKIMTestModeEnabled = "test_mode_enabled"
	DKIMMissing         = "missing_dkim"

	DMARCCompliant   = "dmarc_compliant"
	DMARCMissing     = "missing_dmarc"
	DMARCWeakPolicy  = "weak_dmarc_policy"
	DMARCMissingTags = "dmarc_missing_tags"
)

var (
	// DMARCPrefix matches v=DMARC1 with whitespace (RFC7489).
	DMARCPrefix = regexp.MustCompile(
		`^v\s*=\s*DMARC1`,
	)
	SPFPrefix          = regexp.MustCompile(`^v=(?i)spf1`)
	knownDkimSelectors = []string{
		"x",             // Generic
		"google",        // Google
		"selector1",     // Microsoft
		"selector2",     // Microsoft
		"s1",            // Generic
		"s2",            // Generic
		"k1",            // MailChimp
		"mandrill",      // Mandrill
		"everlytickey1", // Everlytic
		"everlytickey2", // Everlytic
		"dkim",          // Hetzner
		"mxvault",       // MxVault
	}
)

type assessData struct {
	handlesEmail bool
	domainID     int
	txtRecords   []store.TxtRecords
}

func (a *Assessor) assessSPF(ctx context.Context, d assessData) error {
	defer func() { a.logger.DebugContext(ctx, "assess SPF complete", "domain_id", d.domainID) }()

	var spfFound bool
	for _, record := range d.txtRecords {
		if SPFPrefix.MatchString(record.Value) {
			spfFound = true
			recordValue := record.Value

			switch {
			case strings.Contains(recordValue, " ?all"):
				// Weak policy
				if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{Int32: record.ID, Valid: true},
					store.FindingSeverityHigh, store.FindingStatusOpen,
					SPFWeakPolicy, recordValue,
					"SPF policy uses '?all' which is too permissive"); err != nil {
					return err
				}

			case strings.Contains(recordValue, " ~all"):
				// Soft fail policy
				if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{Int32: record.ID, Valid: true},
					store.FindingSeverityMedium, store.FindingStatusOpen,
					SPFSoftFailPolicy, recordValue,
					"SPF policy uses '~all' (soft fail) instead of '-all' (hard fail)"); err != nil {
					return err
				}

			case !strings.Contains(recordValue, "include:") && !strings.Contains(recordValue, "ip4:") && d.handlesEmail:
				// Missing mechanisms
				if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{Int32: record.ID, Valid: true},
					store.FindingSeverityMedium, store.FindingStatusOpen,
					SPFMissingMechanisms, recordValue,
					"SPF record doesn't specify any IP ranges or include directives"); err != nil {
					return err
				}

			case !strings.Contains(recordValue, " all") && !strings.Contains(recordValue, " -all") &&
				!strings.Contains(recordValue, " ~all") && !strings.Contains(recordValue, " ?all"):
				// Missing all mechanism
				if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{Int32: record.ID, Valid: true},
					store.FindingSeverityHigh, store.FindingStatusOpen,
					SPFMissingAllMechanism, recordValue,
					"SPF record does not end with an 'all' mechanism"); err != nil {
					return err
				}

			case strings.Count(recordValue, "include:") > MaxSPFLookups:
				// Excessive lookups
				if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{Int32: record.ID, Valid: true},
					store.FindingSeverityMedium, store.FindingStatusOpen,
					SPFExcessiveLookups, recordValue,
					fmt.Sprintf("SPF record contains %d include mechanisms", strings.Count(recordValue, "include:"))); err != nil {
					return err
				}

			default:
				// If none of the above cases matched, the record is compliant
				if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{Int32: record.ID, Valid: true},
					store.FindingSeverityInfo, store.FindingStatusClosed,
					SPFCompliant, recordValue,
					"SPF record is properly configured with all recommended settings"); err != nil {
					return err
				}
			}
		}
	}

	// Check for missing SPF and handle appropriately
	if !spfFound && d.handlesEmail {
		if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{}, store.FindingSeverityCritical, store.FindingStatusOpen, SPFMissing, "", "No SPF record found for domain that handles email."); err != nil {
			return err
		}
	} else if !spfFound && !d.handlesEmail {
		if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{}, store.FindingSeverityInfo, store.FindingStatusNotApplicable, NotApplicable, "", "SPF record not applicable, domain doesn't handle email."); err != nil {
			return err
		}
	}

	return nil
}

func (a *Assessor) assessDKIM(ctx context.Context, d assessData) error {
	defer func() { a.logger.DebugContext(ctx, "assess DKIM complete", "domain_id", d.domainID) }()

	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		TenantID: pgtype.Int4{Int32: int32(1), Valid: true},
		ID:       int32(d.domainID),
	})
	if err != nil {
		return fmt.Errorf("get domain: %d %w", d.domainID, err)
	}

	domainName := domain.Name
	var dkimFound bool
	var checkedSelectors []string
	dnsClient := dnsclient.New()

	for _, selector := range knownDkimSelectors {
		selectorDomain := fmt.Sprintf("%s._domainkey.%s", selector, domainName)
		checkedSelectors = append(checkedSelectors, selectorDomain)

		dkimRecords, selectorFound := dnsClient.LookupTXT(selectorDomain)

		if selectorFound && len(dkimRecords) > 0 {
			for _, recordValue := range dkimRecords {
				if strings.Contains(recordValue, "v=DKIM") {
					dkimFound = true
					hasIssues := false

					if strings.Contains(recordValue, "k=rsa") && strings.Contains(recordValue, "p=") {
						keyString := extractKeyFromDKIM(recordValue)
						if len(keyString) < MinDKIMKeyLength {
							hasIssues = true
							if err := a.createEmailFinding(ctx, FindingDKIM, d.domainID, pgtype.Int4{},
								store.FindingSeverityHigh, store.FindingStatusOpen,
								DKIMWeakKeyLength, recordValue,
								"DKIM record uses a weak RSA key",
								WithSelector(selector)); err != nil {
								return err
							}
						}
					}

					// check missing tags
					if !strings.Contains(recordValue, "t=") {
						hasIssues = true
						if err := a.createEmailFinding(ctx, FindingDKIM, d.domainID, pgtype.Int4{},
							store.FindingSeverityMedium, store.FindingStatusOpen,
							DKIMMissingTags, recordValue,
							"DKIM record is missing the 't=' flag",
							WithSelector(selector)); err != nil {
							return err
						}
					}

					// check is test mode
					if strings.Contains(recordValue, "t=y") {
						hasIssues = true
						if err := a.createEmailFinding(ctx, FindingDKIM, d.domainID, pgtype.Int4{},
							store.FindingSeverityMedium, store.FindingStatusOpen,
							DKIMTestModeEnabled, recordValue,
							"DKIM record has testing mode enabled",
							WithSelector(selector)); err != nil {
							return err
						}
					}

					// If we've found a DKIM record for this selector but haven't created any findings, it's compliant
					if !hasIssues {
						if err := a.createEmailFinding(ctx, FindingDKIM, d.domainID, pgtype.Int4{},
							store.FindingSeverityInfo, store.FindingStatusClosed,
							DKIMCompliant, recordValue,
							"DKIM record is properly configured with all recommended settings",
							WithSelector(selector)); err != nil {
							return err
						}
					}
				}
			}
		}
	}

	if !dkimFound && d.handlesEmail {
		details := fmt.Sprintf("No DKIM records found for email handling domain. Checked selectors: %s", strings.Join(checkedSelectors, ", "))
		if err := a.createEmailFinding(ctx, FindingDKIM, d.domainID, pgtype.Int4{},
			store.FindingSeverityHigh, store.FindingStatusOpen,
			DKIMMissing, "", details); err != nil {
			return err
		}
	} else if !dkimFound && !d.handlesEmail {
		details := fmt.Sprintf("DKIM record not applicable, domain doesn't handle email. Checked selectors: %s", strings.Join(checkedSelectors, ", "))
		if err := a.createEmailFinding(ctx, FindingDKIM, d.domainID, pgtype.Int4{},
			store.FindingSeverityInfo, store.FindingStatusNotApplicable,
			NotApplicable, "", details); err != nil {
			return err
		}
	}

	return nil
}

// Helper function to extract the key from DKIM record
func extractKeyFromDKIM(dkimRecord string) string {
	if !strings.Contains(dkimRecord, "p=") {
		return ""
	}

	parts := strings.Split(dkimRecord, "p=")
	if len(parts) < 2 {
		return ""
	}

	keyPart := parts[1]
	endIndex := strings.IndexAny(keyPart, ";")
	if endIndex == -1 {
		// If no semicolon, take the whole string
		return keyPart
	}

	return keyPart[:endIndex]
}

func (a *Assessor) assessDMARC(ctx context.Context, d assessData) error {
	defer func() { a.logger.DebugContext(ctx, "assess DMARC complete", "domain_id", d.domainID) }()

	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		TenantID: pgtype.Int4{Int32: int32(1), Valid: true},
		ID:       int32(d.domainID),
	})
	if err != nil {
		return fmt.Errorf("get domain: %d %w", d.domainID, err)
	}
	domainName := domain.Name
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domainName)
	dnsClient := dnsclient.New()
	dmarcRecords, dmarcFound := dnsClient.LookupTXT(dmarcDomain)

	if dmarcFound && len(dmarcRecords) > 0 {
		for _, recordValue := range dmarcRecords {
			if DMARCPrefix.MatchString(recordValue) {
				status := DMARCCompliant // Use the defined constant
				policy := recordValue

				if strings.Contains(recordValue, "p=none") {
					status = DMARCWeakPolicy // Use the defined constant
				}

				if !strings.Contains(recordValue, "rua=") ||
					!strings.Contains(recordValue, "ruf=") {
					if status == DMARCCompliant {
						status = DMARCMissingTags // Use the defined constant
					}
				}

				switch status {
				case DMARCWeakPolicy:
					if err := a.createEmailFinding(ctx, FindingDMARC, d.domainID, pgtype.Int4{},
						store.FindingSeverityHigh, store.FindingStatusOpen,
						DMARCWeakPolicy, recordValue,
						"DMARC policy is set to 'none'",
						WithPolicy(policy)); err != nil {
						return err
					}
					if !strings.Contains(recordValue, "rua=") || !strings.Contains(recordValue, "ruf=") {
						if err := a.createEmailFinding(ctx, FindingDMARC, d.domainID, pgtype.Int4{},
							store.FindingSeverityMedium, store.FindingStatusOpen,
							DMARCMissingTags, recordValue,
							"DMARC record is missing recommended tags (rua, ruf)",
							WithPolicy(policy)); err != nil {
							return err
						}
					}

				case DMARCMissingTags:
					if err := a.createEmailFinding(ctx, FindingDMARC, d.domainID, pgtype.Int4{},
						store.FindingSeverityInfo, store.FindingStatusOpen,
						DMARCMissingTags, recordValue,
						"DMARC record is missing recommended tags (rua, ruf)",
						WithPolicy(policy)); err != nil {
						return err
					}

				default:
					if err := a.createEmailFinding(ctx, FindingDMARC, d.domainID, pgtype.Int4{},
						store.FindingSeverityInfo, store.FindingStatusClosed,
						DMARCCompliant, recordValue,
						"DMARC record uses a strong policy and includes all recommended tags",
						WithPolicy(policy)); err != nil {
						return err
					}
				}
			}
		}
	} else if !dmarcFound && d.handlesEmail {
		// No policy to store when DMARC is missing
		if err := a.createEmailFinding(ctx, FindingDMARC, d.domainID, pgtype.Int4{},
			store.FindingSeverityCritical, store.FindingStatusOpen,
			DMARCMissing, "", "No DMARC record found for domain that handles email."); err != nil {
			return err
		}
	} else if !dmarcFound && !d.handlesEmail {
		if err := a.createEmailFinding(ctx, FindingDMARC, d.domainID, pgtype.Int4{},
			store.FindingSeverityInfo, store.FindingStatusNotApplicable,
			NotApplicable, "", "DMARC record not applicable, domain doesn't handle email"); err != nil {
			return err
		}
	}

	return nil
}

func (a *Assessor) AssessEmailSecurity(ctx context.Context, domainID int) error {
	mxRecords, err := a.store.RecordsGetMXByDomainID(
		ctx,
		pgtype.Int4{Int32: int32(domainID), Valid: true},
	)
	if err != nil {
		return fmt.Errorf("get MX records: %w", err)
	}

	handlesEmail := len(mxRecords) > 0
	txtRecords, err := a.store.RecordsGetTXTByDomainID(
		ctx,
		pgtype.Int4{Int32: int32(domainID), Valid: true},
	)
	if err != nil {
		return fmt.Errorf("get TXT records: %w", err)
	}
	as := assessData{
		handlesEmail: handlesEmail,
		domainID:     domainID,
		txtRecords:   txtRecords,
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return a.assessSPF(ctx, as)
	})
	g.Go(func() error {
		return a.assessDKIM(ctx, as)
	})
	g.Go(func() error {
		return a.assessDMARC(ctx, as)
	})
	if err := g.Wait(); err != nil {
		return fmt.Errorf("assess email security: %w", err)
	}
	return nil
}

// EmailFindingOption represents an option for configuring an email finding
type EmailFindingOption func(*emailFindingParams)

// emailFindingParams holds all possible parameters for email findings
type emailFindingParams struct {
	ctx         context.Context
	findingType string
	domainID    int
	recordID    pgtype.Int4
	severity    store.FindingSeverity
	status      store.FindingStatus
	issueType   string
	recordValue string
	details     string
	selector    string
	policy      string
}

// WithSelector sets the DKIM selector
func WithSelector(selector string) EmailFindingOption {
	return func(p *emailFindingParams) {
		p.selector = selector
	}
}

// WithPolicy sets the DMARC policy
func WithPolicy(policy string) EmailFindingOption {
	return func(p *emailFindingParams) {
		p.policy = policy
	}
}

func (a *Assessor) createEmailFinding(
	ctx context.Context,
	findingType string,
	domainID int,
	recordID pgtype.Int4,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
	recordValue string,
	details string,
	opts ...EmailFindingOption,
) error {
	// Initialize with required parameters
	params := &emailFindingParams{
		ctx:         ctx,
		findingType: findingType,
		domainID:    domainID,
		recordID:    recordID,
		severity:    severity,
		status:      status,
		issueType:   issueType,
		recordValue: recordValue,
		details:     details,
	}

	// Apply all optional parameters
	for _, opt := range opts {
		opt(params)
	}

	switch params.findingType {
	case FindingSPF:
		spfParams := store.AssessCreateSPFFindingParams{
			DomainID:    pgtype.Int4{Int32: int32(params.domainID), Valid: true},
			TxtRecordID: params.recordID,
			Severity:    params.severity,
			Status:      params.status,
			IssueType:   params.issueType,
			SpfValue:    pgtype.Text{String: params.recordValue, Valid: params.recordValue != ""},
			Details:     pgtype.Text{String: params.details, Valid: true},
		}
		return a.createFinding(ctx, spfParams, "create SPF finding", params.issueType)

	case FindingDKIM:
		if params.selector != "" {
			// Use AssessCreateDKIMFindingParams when selector is provided
			dkimParams := store.AssessCreateDKIMFindingParams{
				DomainID:    pgtype.Int4{Int32: int32(params.domainID), Valid: true},
				TxtRecordID: params.recordID,
				Severity:    params.severity,
				Status:      params.status,
				Selector:    pgtype.Text{String: params.selector, Valid: true},
				IssueType:   params.issueType,
				DkimValue:   pgtype.Text{String: params.recordValue, Valid: params.recordValue != ""},
				Details:     pgtype.Text{String: params.details, Valid: true},
			}
			return a.createFinding(ctx, dkimParams, "create DKIM with selector finding", params.issueType)
		}
		// Use AssessCreateDKIMFindingNoSelectorParams when no selector is provided
		dkimParams := store.AssessCreateDKIMFindingNoSelectorParams{
			DomainID:    pgtype.Int4{Int32: int32(params.domainID), Valid: true},
			TxtRecordID: params.recordID,
			Severity:    params.severity,
			Status:      params.status,
			IssueType:   params.issueType,
			DkimValue:   pgtype.Text{String: params.recordValue, Valid: params.recordValue != ""},
			Details:     pgtype.Text{String: params.details, Valid: true},
		}
		return a.createFinding(ctx, dkimParams, "create DKIM no select finding", params.issueType)
	case FindingDMARC:
		dmarcParams := store.AssessCreateDMARCFindingParams{
			DomainID:    pgtype.Int4{Int32: int32(params.domainID), Valid: true},
			TxtRecordID: params.recordID,
			Severity:    params.severity,
			Status:      params.status,
			IssueType:   params.issueType,
			DmarcValue:  pgtype.Text{String: params.recordValue, Valid: params.recordValue != ""},
			Details:     pgtype.Text{String: params.details, Valid: true},
			Policy:      pgtype.Text{String: params.policy, Valid: params.policy != ""},
		}
		//if params.policy != "" {
		//	dmarcParams.Policy = pgtype.Text{String: params.policy, Valid: params.policy != ""}
		//}
		return a.createFinding(ctx, dmarcParams, "create DMARC finding", params.issueType)

	default:
		return fmt.Errorf("invalid finding type: %s", params.findingType)
	}
}
