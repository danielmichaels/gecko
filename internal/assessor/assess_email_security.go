package assessor

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

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
	SPFPermitAll           = "permit_all_spf_policy"
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

	DMARCCompliant           = "dmarc_compliant"
	DMARCMissing             = "missing_dmarc"
	DMARCWeakPolicy          = "weak_dmarc_policy"
	DMARCQuarantinePolicy    = "quarantine_dmarc_policy"
	DMARCReducedPct          = "dmarc_reduced_pct"
	DMARCWeakSubdomainPolicy = "dmarc_weak_subdomain_policy"
	DMARCMissingTags         = "dmarc_missing_tags"
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
	txtRecords   []store.TxtRecords
	mxRecords    []store.MxRecords
	domainID     int
	handlesEmail bool
}

func (a *Assessor) assessSPF(ctx context.Context, d assessData) error {
	defer func() { a.logger.DebugContext(ctx, "assess SPF complete", "domain_id", d.domainID) }()

	var spfFound bool
	for _, record := range d.txtRecords {
		if SPFPrefix.MatchString(record.Value) {
			spfFound = true
			recordValue := record.Value

			switch {
			case spfPermitsAll(recordValue):
				// Permit-all: '+all' (or a bare 'all', which RFC 7208 treats as
				// '+all') authorises any sender and fully defeats SPF.
				if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{Int32: record.ID, Valid: true},
					store.FindingSeverityCritical, store.FindingStatusOpen,
					SPFPermitAll, recordValue,
					"SPF policy permits all senders ('+all'/'all'), allowing anyone to spoof the domain"); err != nil {
					return err
				}

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

			case countSPFDNSLookups(recordValue) > MaxSPFLookups:
				// Excessive lookups
				if err := a.createEmailFinding(ctx, FindingSPF, d.domainID, pgtype.Int4{Int32: record.ID, Valid: true},
					store.FindingSeverityMedium, store.FindingStatusOpen,
					SPFExcessiveLookups, recordValue,
					fmt.Sprintf("SPF record requires %d DNS lookups, exceeding the RFC 7208 limit of %d", countSPFDNSLookups(recordValue), MaxSPFLookups)); err != nil {
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

// spfPermitsAll reports whether an SPF record ends in a permit-all mechanism:
// an explicit '+all' or a bare 'all' (which RFC 7208 §4.6.2 treats as '+all').
// The qualified forms '-all', '~all' and '?all' are excluded.
func spfPermitsAll(record string) bool {
	for _, tok := range strings.Fields(record) {
		if strings.EqualFold(tok, "all") || strings.EqualFold(tok, "+all") {
			return true
		}
	}
	return false
}

// countSPFDNSLookups counts the DNS-lookup-causing mechanisms in an SPF record
// per RFC 7208 §4.6.4 (include, a, mx, ptr, exists, redirect). It does not
// recurse into included records — nested counting is tracked as a follow-up — so
// it under-counts deeply nested policies but no longer ignores everything but
// 'include:'.
func countSPFDNSLookups(record string) int {
	count := 0
	for _, tok := range strings.Fields(record) {
		t := strings.ToLower(strings.TrimLeft(tok, "+-~?"))
		switch {
		case strings.HasPrefix(t, "include:"),
			strings.HasPrefix(t, "exists:"),
			strings.HasPrefix(t, "redirect="),
			t == "a", strings.HasPrefix(t, "a:"), strings.HasPrefix(t, "a/"),
			t == "mx", strings.HasPrefix(t, "mx:"), strings.HasPrefix(t, "mx/"),
			t == "ptr", strings.HasPrefix(t, "ptr:"):
			count++
		}
	}
	return count
}

func (a *Assessor) assessDKIM(ctx context.Context, d assessData, selectors []string) error {
	defer func() { a.logger.DebugContext(ctx, "assess DKIM complete", "domain_id", d.domainID) }()

	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		TenantID: pgtype.Int4{Int32: a.identity.TenantID, Valid: true},
		ID:       int32(d.domainID),
	})
	if err != nil {
		return fmt.Errorf("get domain: %d %w", d.domainID, err)
	}

	domainName := domain.Name
	var foundValidDKIM bool
	var validSelectors []string

	if len(selectors) == 0 {
		selectors = knownDkimSelectors
	}

	for _, selector := range selectors {
		selectorDomain := fmt.Sprintf("%s._domainkey.%s", selector, domainName)

		dkimRecords, selectorFound := a.dnsClient.LookupTXT(selectorDomain)

		if selectorFound && len(dkimRecords) > 0 {
			for _, recordValue := range dkimRecords {
				if strings.Contains(recordValue, "v=DKIM") {
					foundValidDKIM = true
					validSelectors = append(validSelectors, selector)

					hasIssues := false

					if strings.Contains(recordValue, "k=rsa") &&
						strings.Contains(recordValue, "p=") {
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

					// recommended key-type tag absent (defaults to rsa, but k= is
					// recommended for clarity per RFC 6376)
					if !strings.Contains(recordValue, "k=") {
						hasIssues = true
						if err := a.createEmailFinding(ctx, FindingDKIM, d.domainID, pgtype.Int4{},
							store.FindingSeverityInfo, store.FindingStatusOpen,
							DKIMMissingTags, recordValue,
							"DKIM record omits the recommended 'k=' key-type tag",
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

	// Only create a single "missing DKIM" finding if no valid DKIM records were found
	if !foundValidDKIM && d.handlesEmail {
		details := fmt.Sprintf(
			"No DKIM records found for any common selectors and domain has MX records. Checked: %s",
			strings.Join(selectors, ", "),
		)
		if err := a.createEmailFinding(ctx, FindingDKIM, d.domainID, pgtype.Int4{},
			store.FindingSeverityHigh, store.FindingStatusOpen,
			DKIMMissing, "", details); err != nil {
			return err
		}
	} else if !d.handlesEmail {
		details := fmt.Sprintf("DKIM not applicable for domain that doesn't handle email. Checked selectors: %s", strings.Join(selectors, ", "))
		if err := a.createEmailFinding(ctx, FindingDKIM, d.domainID, pgtype.Int4{},
			store.FindingSeverityInfo, store.FindingStatusNotApplicable,
			NotApplicable, "", details); err != nil {
			return err
		}
	} else {
		// If we found valid DKIM records, log which selectors were valid
		a.logger.DebugContext(ctx, "found valid DKIM records",
			"domain_id", d.domainID,
			"valid_selectors", strings.Join(validSelectors, ", "))
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
		TenantID: pgtype.Int4{Int32: a.identity.TenantID, Valid: true},
		ID:       int32(d.domainID),
	})
	if err != nil {
		return fmt.Errorf("get domain: %d %w", d.domainID, err)
	}
	domainName := domain.Name
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domainName)
	dmarcRecords, dmarcFound := a.dnsClient.LookupTXT(dmarcDomain)

	if dmarcFound && len(dmarcRecords) > 0 {
		for _, recordValue := range dmarcRecords {
			if !DMARCPrefix.MatchString(recordValue) {
				continue
			}
			if err := a.assessDMARCRecord(ctx, d, recordValue); err != nil {
				return err
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

// assessDMARCRecord grades a single DMARC record: it distinguishes enforcement
// strength (reject > quarantine > none), flags partial coverage (pct<100) and a
// weaker subdomain policy (sp=), and reports missing reporting tags. A clean
// 'p=reject' with full coverage and reporting tags is the only compliant verdict.
func (a *Assessor) assessDMARCRecord(ctx context.Context, d assessData, record string) error {
	emit := func(sev store.FindingSeverity, status store.FindingStatus, issueType, details string) error {
		return a.createEmailFinding(ctx, FindingDMARC, d.domainID, pgtype.Int4{},
			sev, status, issueType, record, details, WithPolicy(record))
	}

	tags := parseDMARCTags(record)
	policy := tags["p"]
	subPolicy := tags["sp"]
	missingTags := tags["rua"] == "" || tags["ruf"] == ""
	pct := dmarcPct(tags)
	enforcing := policy == "quarantine" || policy == "reject"

	switch policy {
	case "reject":
		// strongest policy; the compliant verdict is decided below.
	case "quarantine":
		if err := emit(store.FindingSeverityMedium, store.FindingStatusOpen, DMARCQuarantinePolicy,
			"DMARC policy is 'quarantine'; 'reject' is recommended for full enforcement"); err != nil {
			return err
		}
	default:
		if err := emit(store.FindingSeverityHigh, store.FindingStatusOpen, DMARCWeakPolicy,
			"DMARC policy is 'none' (monitoring only) and does not enforce"); err != nil {
			return err
		}
	}

	spWeaker := subPolicy != "" && dmarcPolicyRank(subPolicy) < dmarcPolicyRank(policy)
	if enforcing {
		if pct < 100 {
			if err := emit(store.FindingSeverityMedium, store.FindingStatusOpen, DMARCReducedPct,
				fmt.Sprintf("DMARC pct=%d applies the policy to only part of the mail stream", pct)); err != nil {
				return err
			}
		}
		if spWeaker {
			if err := emit(store.FindingSeverityMedium, store.FindingStatusOpen, DMARCWeakSubdomainPolicy,
				fmt.Sprintf("DMARC subdomain policy 'sp=%s' is weaker than the domain policy 'p=%s'", subPolicy, policy)); err != nil {
				return err
			}
		}
	}

	if missingTags {
		if err := emit(store.FindingSeverityInfo, store.FindingStatusOpen, DMARCMissingTags,
			"DMARC record is missing recommended reporting tags (rua, ruf)"); err != nil {
			return err
		}
	}

	if policy == "reject" && !missingTags && pct >= 100 && !spWeaker {
		if err := emit(store.FindingSeverityInfo, store.FindingStatusClosed, DMARCCompliant,
			"DMARC uses 'p=reject' with full coverage and reporting tags"); err != nil {
			return err
		}
	}
	return nil
}

// parseDMARCTags splits a DMARC record into its tag=value pairs (lower-cased keys).
func parseDMARCTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	return tags
}

// dmarcPct returns the effective DMARC pct (defaulting to 100 when absent or
// unparseable).
func dmarcPct(tags map[string]string) int {
	v, ok := tags["pct"]
	if !ok || v == "" {
		return 100
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 100
	}
	return n
}

// dmarcPolicyRank orders DMARC policies by enforcement strength.
func dmarcPolicyRank(p string) int {
	switch p {
	case "reject":
		return 2
	case "quarantine":
		return 1
	default:
		return 0
	}
}

// hasDeliverableMX reports whether the domain has at least one real MX target.
// A null-MX (RFC 7505: target ".") is an explicit "no mail" declaration and does
// not count.
func hasDeliverableMX(mxRecords []store.MxRecords) bool {
	for _, mx := range mxRecords {
		if strings.TrimSuffix(strings.TrimSpace(mx.Target), ".") != "" {
			return true
		}
	}
	return false
}

func (a *Assessor) AssessEmailSecurity(ctx context.Context, domainID int) error {
	mxRecords, err := a.store.RecordsGetMXByDomainID(
		ctx,
		pgtype.Int4{Int32: int32(domainID), Valid: true},
	)
	if err != nil {
		return fmt.Errorf("get MX records: %w", err)
	}

	// An explicit null-MX (RFC 7505: a single "0 .") declares that the domain
	// neither sends nor receives mail, so email-auth records are not applicable.
	handlesEmail := hasDeliverableMX(mxRecords)
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
		mxRecords:    mxRecords,
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return a.assessSPF(ctx, as)
	})
	g.Go(func() error {
		return a.assessDKIM(ctx, as, knownDkimSelectors)
	})
	g.Go(func() error {
		return a.assessDMARC(ctx, as)
	})
	g.Go(func() error {
		return a.assessBIMI(ctx, as)
	})
	g.Go(func() error {
		return a.assessMTASTS(ctx, as)
	})
	g.Go(func() error {
		return a.assessTLSRPT(ctx, as)
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
	severity    store.FindingSeverity
	status      store.FindingStatus
	issueType   string
	recordValue string
	details     string
	selector    string
	policy      string
	domainID    int
	recordID    pgtype.Int4
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

// createEmailFinding creates a finding for an email security issue based on the provided parameters.
// It supports creating findings for different email security record types like SPF, DKIM, and DMARC.
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
				DkimValue: pgtype.Text{
					String: params.recordValue,
					Valid:  params.recordValue != "",
				},
				Details: pgtype.Text{String: params.details, Valid: true},
			}
			return a.createFinding(
				ctx,
				dkimParams,
				"create DKIM with selector finding",
				params.issueType,
			)
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
		return a.createFinding(ctx, dmarcParams, "create DMARC finding", params.issueType)

	default:
		return fmt.Errorf("invalid finding type: %s", params.findingType)
	}
}
