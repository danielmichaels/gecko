package assessor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// FindingsContainer aggregates and organizes security findings from a zone transfer analysis
// including primary findings, sensitive information, internal exposure, and security issues
type FindingsContainer struct {
	RecordData       map[string][]any       `json:"raw_record_data"`
	PrimaryFinding   Finding                `json:"primary_finding"`
	Assessment       ZoneTransferAssessment `json:"assessment_data"`
	SensitiveInfo    []Finding              `json:"sensitive_info_findings,omitempty"`
	InternalExposure []Finding              `json:"internal_exposure_findings,omitempty"`
	SecurityIssues   []Finding              `json:"security_issues_findings,omitempty"`
}

// Finding represents a single security finding
type Finding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
}

// ZoneTransferAssessment contains all assessment data extracted from zone transfer results
type ZoneTransferAssessment struct {
	RecordCounts     RecordCountMetrics   `json:"record_counts"`
	SensitiveInfo    SensitiveInformation `json:"sensitive_info"`
	InternalExposure ExposureMetrics      `json:"internal_exposure"`
	SecurityFlags    SecurityWarnings     `json:"security_flags"`
}

// RecordCountMetrics tracks statistics about the DNS records discovered
type RecordCountMetrics struct {
	ByType map[string]int `json:"by_type"`
	Total  int            `json:"total"`
}

// SensitiveInformation captures potentially sensitive data exposed in records
type SensitiveInformation struct {
	EmailAddresses []string `json:"email_addresses"`
	InternalHosts  []string `json:"internal_hosts"`
	Credentials    []string `json:"credentials"`
	ApiKeys        []string `json:"api_keys"`
}

// ExposureMetrics quantifies the exposure of internal infrastructure
type ExposureMetrics struct {
	InternalIPs    []string `json:"internal_ips"`
	DevelopmentEnv []string `json:"development_environments"`
}

// SecurityWarnings identifies specific security issues found
type SecurityWarnings struct {
	SpfIssues      []string `json:"spf_issues"`
	DkimIssues     []string `json:"dkim_issues"`
	DmarcIssues    []string `json:"dmarc_issues"`
	SuspiciousText []string `json:"suspicious_text"`
}

// AssessZoneTransfer performs a security assessment of DNS zone transfer capabilities for a given domain.
// It retrieves zone transfer attempts, analyzes the results, and stores findings related to potential
// DNS information exposure risks. Returns an error if the assessment process fails.
func (a *Assessor) AssessZoneTransfer(ctx context.Context, domainUID string) error {
	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: 1, Valid: true}, // todo: replace with actual tenant ID
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			a.logger.WarnContext(
				ctx,
				"Domain not found in database, cannot scan zone transfer",
				"domain",
				domain.Uid,
			)
			return fmt.Errorf("domain %s not found in database", domain.Uid)
		}
		a.logger.ErrorContext(ctx, "Error looking up domain", "domain", domain.Uid, "error", err)
		return err
	}
	attempts, err := a.store.ScannersGetZoneTransferAttempts(
		ctx,
		pgtype.Int4{Int32: domain.ID, Valid: true},
	)
	if err != nil {
		a.logger.ErrorContext(ctx, "Failed to retrieve zone transfer attempts", "error", err)
		return err
	}
	successfulAssessments := 0
	for _, attempt := range attempts {
		if attempt.WasSuccessful {
			var transferData dnsrecords.ZoneTransferData
			if err := json.Unmarshal(attempt.ResponseData, &transferData); err != nil {
				a.logger.ErrorContext(
					ctx,
					"Failed to unmarshal zone transfer data",
					"error",
					err,
					"nameserver",
					attempt.Nameserver,
				)
				continue
			}
			assessment := ExtractZoneTransferAssessment(&transferData)

			recordData := extractRecordDataByType(&transferData)
			findings := FindingsContainer{
				PrimaryFinding: Finding{
					Title: fmt.Sprintf(
						"Zone transfer (%s) allowed from nameserver %s",
						attempt.TransferType,
						attempt.Nameserver,
					),
					Severity: string(store.FindingSeverityCritical),
					Details: fmt.Sprintf(
						"Zone transfer (%s) allowed from nameserver %s. This can leak internal DNS information to attackers.",
						attempt.TransferType,
						attempt.Nameserver,
					),
				},
				Assessment: assessment,
				RecordData: recordData,
			}

			findings.SensitiveInfo = collectSensitiveInfoFindings(assessment)
			findings.InternalExposure = collectInternalExposureFindings(assessment)
			findings.SecurityIssues = collectSecurityFlagFindings(assessment)
			findingsJSON, err := json.Marshal(findings)
			if err != nil {
				a.logger.ErrorContext(ctx, "Failed to marshal findings data", "error", err)
				continue
			}

			err = a.store.StoreZoneTransferFinding(ctx, store.StoreZoneTransferFindingParams{
				DomainID:             pgtype.Int4{Int32: domain.ID, Valid: true},
				Severity:             store.FindingSeverityCritical,
				Status:               store.FindingStatusOpen,
				Nameserver:           attempt.Nameserver,
				ZoneTransferPossible: true,
				TransferType:         attempt.TransferType,
				TransferDetails:      findingsJSON,
			})
			if err != nil {
				a.logger.ErrorContext(ctx, "Failed to store zone transfer finding", "error", err)
				continue
			}
			successfulAssessments++
		}
	}

	if successfulAssessments > 0 {
		a.logger.InfoContext(
			ctx,
			"Successfully assessed zone transfers",
			"domain",
			domain.Uid,
			"count",
			successfulAssessments,
		)
		return nil
	}
	a.logger.InfoContext(ctx, "No zone transfer attempts found to assess", "domain", domain.Uid)

	return nil
}

// extractRecordDataByType categorizes DNS records from a zone transfer by their record type.
// It returns a map where keys are record types and values are slices of simplified record data.
func extractRecordDataByType(transferData *dnsrecords.ZoneTransferData) map[string][]any {
	recordsByType := make(map[string][]any)

	allRecords := append(transferData.Records.AXFR, transferData.Records.IXFR...)

	for _, record := range allRecords {
		recordType := record.Type

		if _, exists := recordsByType[recordType]; !exists {
			recordsByType[recordType] = make([]any, 0)
		}

		simplifiedRecord := map[string]any{
			"name": record.Name,
			"ttl":  record.TTL,
			"data": record.Data,
		}

		recordsByType[recordType] = append(recordsByType[recordType], simplifiedRecord)
	}

	return recordsByType
}

// collectSensitiveInfoFindings generates a list of findings based on sensitive information discovered during a zone transfer assessment.
// It analyzes exposed email addresses, credentials, API keys, and internal hostnames, creating detailed findings with appropriate severity levels.
func collectSensitiveInfoFindings(assessment ZoneTransferAssessment) []Finding {
	var findings []Finding

	if len(assessment.SensitiveInfo.EmailAddresses) > 0 {
		details := fmt.Sprintf("Zone transfer exposed %d email addresses including: %s",
			len(assessment.SensitiveInfo.EmailAddresses),
			joinWithLimit(assessment.SensitiveInfo.EmailAddresses, 5))

		findings = append(findings, Finding{
			Title:    "Email addresses exposed in zone transfer",
			Severity: string(store.FindingSeverityMedium),
			Details:  details,
		})
	}

	if len(assessment.SensitiveInfo.Credentials) > 0 {
		details := fmt.Sprintf("Zone transfer exposed %d possible credentials or secrets",
			len(assessment.SensitiveInfo.Credentials))

		findings = append(findings, Finding{
			Title:    "Credentials exposed in zone transfer",
			Severity: string(store.FindingSeverityCritical),
			Details:  details,
		})
	}

	if len(assessment.SensitiveInfo.ApiKeys) > 0 {
		details := fmt.Sprintf("Zone transfer exposed %d possible API keys or tokens",
			len(assessment.SensitiveInfo.ApiKeys))

		findings = append(findings, Finding{
			Title:    "API keys exposed in zone transfer",
			Severity: string(store.FindingSeverityCritical),
			Details:  details,
		})
	}

	if len(assessment.SensitiveInfo.InternalHosts) > 0 {
		details := fmt.Sprintf("Zone transfer exposed %d internal hostnames including: %s",
			len(assessment.SensitiveInfo.InternalHosts),
			joinWithLimit(assessment.SensitiveInfo.InternalHosts, 5))

		findings = append(findings, Finding{
			Title:    "Internal hostnames exposed in zone transfer",
			Severity: string(store.FindingSeverityMedium),
			Details:  details,
		})
	}

	return findings
}

// collectInternalExposureFindings collects all internal exposure findings
func collectInternalExposureFindings(assessment ZoneTransferAssessment) []Finding {
	var findings []Finding

	if len(assessment.InternalExposure.InternalIPs) > 0 {
		details := fmt.Sprintf("Zone transfer exposed %d internal IP addresses including: %s",
			len(assessment.InternalExposure.InternalIPs),
			joinWithLimit(assessment.InternalExposure.InternalIPs, 5))

		findings = append(findings, Finding{
			Title:    "Internal IP addresses exposed in zone transfer",
			Severity: string(store.FindingSeverityHigh),
			Details:  details,
		})
	}

	if len(assessment.InternalExposure.DevelopmentEnv) > 0 {
		details := fmt.Sprintf(
			"Zone transfer exposed %d development/test environment hostnames including: %s",
			len(assessment.InternalExposure.DevelopmentEnv),
			joinWithLimit(assessment.InternalExposure.DevelopmentEnv, 5),
		)

		findings = append(findings, Finding{
			Title:    "Development environments exposed in zone transfer",
			Severity: string(store.FindingSeverityMedium),
			Details:  details,
		})
	}

	return findings
}

// collectSecurityFlagFindings collects all security flag findings
func collectSecurityFlagFindings(assessment ZoneTransferAssessment) []Finding {
	var findings []Finding

	if len(assessment.SecurityFlags.SpfIssues) > 0 {
		details := fmt.Sprintf("Zone transfer revealed %d SPF configuration issues: %s",
			len(assessment.SecurityFlags.SpfIssues),
			joinWithLimit(assessment.SecurityFlags.SpfIssues, 3))

		findings = append(findings, Finding{
			Title:    "SPF configuration issues identified",
			Severity: string(store.FindingSeverityMedium),
			Details:  details,
		})
	}

	if len(assessment.SecurityFlags.DmarcIssues) > 0 {
		details := fmt.Sprintf("Zone transfer revealed %d DMARC configuration issues: %s",
			len(assessment.SecurityFlags.DmarcIssues),
			joinWithLimit(assessment.SecurityFlags.DmarcIssues, 3))

		findings = append(findings, Finding{
			Title:    "DMARC configuration issues identified",
			Severity: string(store.FindingSeverityMedium),
			Details:  details,
		})
	}

	if len(assessment.SecurityFlags.SuspiciousText) > 0 {
		details := fmt.Sprintf(
			"Zone transfer revealed %d suspicious text patterns in DNS records that may indicate security issues",
			len(assessment.SecurityFlags.SuspiciousText),
		)

		findings = append(findings, Finding{
			Title:    "Suspicious text patterns in DNS records",
			Severity: string(store.FindingSeverityMedium),
			Details:  details,
		})
	}

	return findings
}

// joinWithLimit joins a slice of strings with commas, limiting to the specified maximum number of items
func joinWithLimit(items []string, maxItems int) string {
	if len(items) <= maxItems {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxItems], ", ") + fmt.Sprintf(", and %d more", len(items)-maxItems)
}

// ExtractZoneTransferAssessment extracts assessment data from zone transfer results
func ExtractZoneTransferAssessment(
	transferData *dnsrecords.ZoneTransferData,
) ZoneTransferAssessment {
	assessment := ZoneTransferAssessment{
		RecordCounts: RecordCountMetrics{
			Total:  transferData.RecordCounts.Total,
			ByType: getRecordTypeCounts(transferData),
		},
		SensitiveInfo:    extractSensitiveInfo(transferData),
		InternalExposure: detectInternalExposure(transferData),
		SecurityFlags:    identifySecurityFlags(transferData),
	}

	return assessment
}

// getRecordTypeCounts analyzes records and returns counts by DNS record type
func getRecordTypeCounts(data *dnsrecords.ZoneTransferData) map[string]int {
	typeCounts := make(map[string]int)

	// Count records from both AXFR and IXFR transfers
	for _, record := range data.Records.AXFR {
		typeCounts[record.Type]++
	}

	for _, record := range data.Records.IXFR {
		typeCounts[record.Type]++
	}

	return typeCounts
}

// extractSensitiveInfo identifies potentially sensitive information in DNS records
func extractSensitiveInfo(data *dnsrecords.ZoneTransferData) SensitiveInformation {
	var info SensitiveInformation

	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	apiKeyRegex := regexp.MustCompile(
		`(?i)(api_?key|access_?key|secret|token)[=:]\s*['"]?([a-zA-Z0-9]{16,})['"]?`,
	)
	credRegex := regexp.MustCompile(
		`(?i)(password|passwd|pwd|user|username)[=:]\s*['"]?([^'"]{3,})['"]?`,
	)

	// check all TXT records for sensitive data
	allRecords := append(data.Records.AXFR, data.Records.IXFR...)
	for _, record := range allRecords {
		if record.Type == "TXT" {
			if txtValues, ok := record.Data["txt"].([]interface{}); ok {
				for _, txtVal := range txtValues {
					content, ok := txtVal.(string)
					if !ok {
						continue
					}
					emails := emailRegex.FindAllString(content, -1)
					info.EmailAddresses = append(info.EmailAddresses, emails...)

					if apiMatches := apiKeyRegex.FindStringSubmatch(content); len(apiMatches) > 2 {
						info.ApiKeys = append(info.ApiKeys, apiMatches[2])
					}

					if credMatches := credRegex.FindStringSubmatch(content); len(credMatches) > 2 {
						info.Credentials = append(info.Credentials, credMatches[0])
					}
				}
			}
		}

		if record.Type == "SOA" {
			if mbox, ok := record.Data["mbox"].(string); ok {
				info.EmailAddresses = append(info.EmailAddresses, mbox)
			}
		}
	}

	internalKeywords := []string{
		"internal", "dev", "staging", "test", "uat", "qa", "preprod",
		"pre-prod", "sandbox", "sbox", "lab", "poc", "demo", "beta",
		"local", "private", "corp", "corporate", "intranet", "admin",
		"build", "jenkins", "ci", "cd", "stg", "int", "integration",
		"legacy", "deprecated", "old", "new", "backup", "bak", "tmp",
		"temp", "testing", "development", "hidden", "restricted", "secure",
	}
	for _, record := range allRecords {
		if record.Type == "A" {
			host := record.Name
			for _, keyword := range internalKeywords {
				if strings.Contains(host, keyword) {
					info.InternalHosts = append(info.InternalHosts, host)
				}
			}
		}
	}

	info.EmailAddresses = removeDuplicates(info.EmailAddresses)
	info.InternalHosts = removeDuplicates(info.InternalHosts)
	info.Credentials = removeDuplicates(info.Credentials)
	info.ApiKeys = removeDuplicates(info.ApiKeys)
	return info
}

// detectInternalExposure identifies exposed internal infrastructure
func detectInternalExposure(data *dnsrecords.ZoneTransferData) ExposureMetrics {
	var metrics ExposureMetrics

	devEnvKeywords := []string{
		"dev.", "staging.", "test.", "uat.", "qa.", "preprod.", "pre-prod.",
		"sandbox.", "sbox.", "lab.", "poc.", "demo.", "beta.", "alpha.",
		"local.", "int.", "integration.", "build.", "jenkins.", "ci.", "cd.",
		"stg.", "development.", "testing.", "tmp.", "temp.",
	}

	allRecords := append(data.Records.AXFR, data.Records.IXFR...)
	for _, record := range allRecords {
		if record.Type == "A" && record.Data != nil {
			ipStr, ok := record.Data["ip"].(string)
			if !ok {
				continue
			}

			// check if this is a development environment by hostname
			name := strings.ToLower(record.Name)
			for _, keyword := range devEnvKeywords {
				if strings.Contains(name, keyword) {
					metrics.DevelopmentEnv = append(metrics.DevelopmentEnv, record.Name)
					break
				}
			}

			ip := net.ParseIP(ipStr)
			if ip != nil && ip.IsPrivate() {
				metrics.InternalIPs = append(metrics.InternalIPs, ipStr)
			}
		}
	}

	metrics.InternalIPs = removeDuplicates(metrics.InternalIPs)
	metrics.DevelopmentEnv = removeDuplicates(metrics.DevelopmentEnv)
	return metrics
}

// identifySecurityFlags detects security issues in DNS records
func identifySecurityFlags(data *dnsrecords.ZoneTransferData) SecurityWarnings {
	var warnings SecurityWarnings

	suspiciousPatterns := []string{
		"password", "user", "login", "admin", "root", "key", "<script",
		"SELECT", "UNION", "INSERT", "DELETE", "UPDATE", "DROP", "ALTER", "TRUNCATE",
		"exec", "eval", "bash", "cmd", "powershell", "curl", "wget",
	}

	allRecords := append(data.Records.AXFR, data.Records.IXFR...)
	for _, record := range allRecords {
		if record.Type == "TXT" {
			txtValues, ok := record.Data["txt"].([]interface{})
			if !ok {
				continue
			}

			for _, txtVal := range txtValues {
				content, ok := txtVal.(string)
				if !ok {
					continue
				}

				lowerContent := strings.ToLower(content)

				if strings.HasPrefix(lowerContent, "v=spf1") {
					if strings.Contains(lowerContent, "all") &&
						!strings.Contains(lowerContent, "-all") {
						warnings.SpfIssues = append(warnings.SpfIssues,
							"SPF record uses potentially unsafe qualifier: "+content)
					}
				}

				if strings.HasPrefix(lowerContent, "v=dmarc1") {
					if strings.Contains(lowerContent, "p=none") {
						warnings.DmarcIssues = append(warnings.DmarcIssues,
							"DMARC policy set to 'none' (monitoring only): "+content)
					}
				}

				for _, pattern := range suspiciousPatterns {
					if strings.Contains(lowerContent, pattern) {
						warnings.SuspiciousText = append(warnings.SuspiciousText,
							fmt.Sprintf("Suspicious pattern '%s' found in TXT record: %s",
								pattern, content))
						break
					}
				}
			}
		}
	}

	warnings.SpfIssues = removeDuplicates(warnings.SpfIssues)
	warnings.DkimIssues = removeDuplicates(warnings.DkimIssues)
	warnings.DmarcIssues = removeDuplicates(warnings.DmarcIssues)
	warnings.SuspiciousText = removeDuplicates(warnings.SuspiciousText)
	return warnings
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if _, exists := seen[item]; !exists {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
