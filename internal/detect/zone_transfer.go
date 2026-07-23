package detect

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/danielmichaels/gecko/internal/checks"
	"github.com/danielmichaels/gecko/internal/dnsrecords"
)

const CheckZoneTransfer = "zone_transfer"

const IssueZoneTransferExposed = "zone_transfer_exposed"

// ZoneTransferAttemptEvidence is one nameserver's zone-transfer attempt outcome.
// Successful is the load-bearing fact (a successful AXFR/IXFR is critical);
// ResponseData carries the transferred zone (dnsrecords.ZoneTransferData) for the
// deeper sensitive-data analysis and is best-effort -- a parse failure degrades
// only the evidence detail, never the finding itself.
type ZoneTransferAttemptEvidence struct {
	Nameserver   string          `json:"nameserver"`
	TransferType string          `json:"transfer_type"`
	ResponseData json.RawMessage `json:"response_data"`
	Successful   bool            `json:"successful"`
}

type ZoneTransferEvidence struct {
	Attempts []ZoneTransferAttemptEvidence `json:"attempts"`
}

type ZoneTransferDetector struct{}

func (ZoneTransferDetector) Kind() string                { return CheckZoneTransfer }
func (ZoneTransferDetector) Scope() checks.EvidenceScope { return checks.SingleAsset }

// Detect emits one critical finding per nameserver that allowed a zone transfer.
// A refused transfer is compliant and yields nothing (absence).
func (ZoneTransferDetector) Detect(ev ZoneTransferEvidence) (checks.DetectResult, error) {
	var out []checks.Finding
	for _, at := range ev.Attempts {
		if !at.Successful {
			continue
		}
		var td dnsrecords.ZoneTransferData
		_ = json.Unmarshal(at.ResponseData, &td) // best-effort; zero value is fine

		assessment := ExtractZoneTransferAssessment(&td)
		container := findingsContainer{
			PrimaryFinding: ztFinding{
				Title: fmt.Sprintf("Zone transfer (%s) allowed from nameserver %s",
					at.TransferType, at.Nameserver),
				Severity: "critical",
				Details: fmt.Sprintf(
					"Zone transfer (%s) allowed from nameserver %s. This can leak internal DNS information to attackers.",
					at.TransferType,
					at.Nameserver,
				),
			},
			Assessment:       assessment,
			RecordData:       extractRecordDataByType(&td),
			SensitiveInfo:    collectSensitiveInfoFindings(assessment),
			InternalExposure: collectInternalExposureFindings(assessment),
			SecurityIssues:   collectSecurityFlagFindings(assessment),
		}
		evJSON, _ := json.Marshal(container)
		out = append(out, checks.Finding{
			IssueType: IssueZoneTransferExposed,
			EntityKey: at.Nameserver,
			Severity:  "critical",
			Title:     container.PrimaryFinding.Title,
			Details:   container.PrimaryFinding.Details,
			Evidence:  evJSON,
		})
	}
	return checks.DetectResult{Found: out}, nil
}

// --- pure zone-transfer analysis (lifted verbatim from the assessor) ---

type findingsContainer struct {
	RecordData       map[string][]any       `json:"raw_record_data"`
	PrimaryFinding   ztFinding              `json:"primary_finding"`
	Assessment       ZoneTransferAssessment `json:"assessment_data"`
	SensitiveInfo    []ztFinding            `json:"sensitive_info_findings,omitempty"`
	InternalExposure []ztFinding            `json:"internal_exposure_findings,omitempty"`
	SecurityIssues   []ztFinding            `json:"security_issues_findings,omitempty"`
}

type ztFinding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
}

type ZoneTransferAssessment struct {
	RecordCounts     RecordCountMetrics   `json:"record_counts"`
	SensitiveInfo    SensitiveInformation `json:"sensitive_info"`
	InternalExposure ExposureMetrics      `json:"internal_exposure"`
	SecurityFlags    SecurityWarnings     `json:"security_flags"`
}

type RecordCountMetrics struct {
	ByType map[string]int `json:"by_type"`
	Total  int            `json:"total"`
}

type SensitiveInformation struct {
	EmailAddresses []string `json:"email_addresses"`
	InternalHosts  []string `json:"internal_hosts"`
	Credentials    []string `json:"credentials"`
	ApiKeys        []string `json:"api_keys"`
}

type ExposureMetrics struct {
	InternalIPs    []string `json:"internal_ips"`
	DevelopmentEnv []string `json:"development_environments"`
}

type SecurityWarnings struct {
	SpfIssues      []string `json:"spf_issues"`
	DkimIssues     []string `json:"dkim_issues"`
	DmarcIssues    []string `json:"dmarc_issues"`
	SuspiciousText []string `json:"suspicious_text"`
}

func ExtractZoneTransferAssessment(td *dnsrecords.ZoneTransferData) ZoneTransferAssessment {
	return ZoneTransferAssessment{
		RecordCounts: RecordCountMetrics{
			Total:  td.RecordCounts.Total,
			ByType: getRecordTypeCounts(td),
		},
		SensitiveInfo:    extractSensitiveInfo(td),
		InternalExposure: detectInternalExposure(td),
		SecurityFlags:    identifySecurityFlags(td),
	}
}

func extractRecordDataByType(td *dnsrecords.ZoneTransferData) map[string][]any {
	byType := make(map[string][]any)
	for _, r := range append(td.Records.AXFR, td.Records.IXFR...) {
		byType[r.Type] = append(byType[r.Type], map[string]any{
			"name": r.Name, "ttl": r.TTL, "data": r.Data,
		})
	}
	return byType
}

func getRecordTypeCounts(data *dnsrecords.ZoneTransferData) map[string]int {
	counts := make(map[string]int)
	for _, r := range append(data.Records.AXFR, data.Records.IXFR...) {
		counts[r.Type]++
	}
	return counts
}

func extractSensitiveInfo(data *dnsrecords.ZoneTransferData) SensitiveInformation {
	var info SensitiveInformation
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	apiKeyRegex := regexp.MustCompile(
		`(?i)(api_?key|access_?key|secret|token)[=:]\s*['"]?([a-zA-Z0-9]{16,})['"]?`,
	)
	credRegex := regexp.MustCompile(
		`(?i)(password|passwd|pwd|user|username)[=:]\s*['"]?([^'"]{3,})['"]?`,
	)

	allRecords := append(data.Records.AXFR, data.Records.IXFR...)
	for _, record := range allRecords {
		if record.Type == "TXT" {
			if txtValues, ok := record.Data["txt"].([]any); ok {
				for _, txtVal := range txtValues {
					content, ok := txtVal.(string)
					if !ok {
						continue
					}
					info.EmailAddresses = append(
						info.EmailAddresses,
						emailRegex.FindAllString(content, -1)...,
					)
					if m := apiKeyRegex.FindStringSubmatch(content); len(m) > 2 {
						info.ApiKeys = append(info.ApiKeys, m[2])
					}
					if m := credRegex.FindStringSubmatch(content); len(m) > 2 {
						info.Credentials = append(info.Credentials, m[0])
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
			for _, keyword := range internalKeywords {
				if strings.Contains(record.Name, keyword) {
					info.InternalHosts = append(info.InternalHosts, record.Name)
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

func detectInternalExposure(data *dnsrecords.ZoneTransferData) ExposureMetrics {
	var metrics ExposureMetrics
	devEnvKeywords := []string{
		"dev.", "staging.", "test.", "uat.", "qa.", "preprod.", "pre-prod.",
		"sandbox.", "sbox.", "lab.", "poc.", "demo.", "beta.", "alpha.",
		"local.", "int.", "integration.", "build.", "jenkins.", "ci.", "cd.",
		"stg.", "development.", "testing.", "tmp.", "temp.",
	}
	for _, record := range append(data.Records.AXFR, data.Records.IXFR...) {
		if record.Type == "A" && record.Data != nil {
			ipStr, ok := record.Data["ip"].(string)
			if !ok {
				continue
			}
			name := strings.ToLower(record.Name)
			for _, keyword := range devEnvKeywords {
				if strings.Contains(name, keyword) {
					metrics.DevelopmentEnv = append(metrics.DevelopmentEnv, record.Name)
					break
				}
			}
			if ip := net.ParseIP(ipStr); ip != nil && ip.IsPrivate() {
				metrics.InternalIPs = append(metrics.InternalIPs, ipStr)
			}
		}
	}
	metrics.InternalIPs = removeDuplicates(metrics.InternalIPs)
	metrics.DevelopmentEnv = removeDuplicates(metrics.DevelopmentEnv)
	return metrics
}

func identifySecurityFlags(data *dnsrecords.ZoneTransferData) SecurityWarnings {
	var warnings SecurityWarnings
	suspiciousPatterns := []string{
		"password", "user", "login", "admin", "root", "key", "<script",
		"SELECT", "UNION", "INSERT", "DELETE", "UPDATE", "DROP", "ALTER", "TRUNCATE",
		"exec", "eval", "bash", "cmd", "powershell", "curl", "wget",
	}
	for _, record := range append(data.Records.AXFR, data.Records.IXFR...) {
		if record.Type != "TXT" {
			continue
		}
		txtValues, ok := record.Data["txt"].([]any)
		if !ok {
			continue
		}
		for _, txtVal := range txtValues {
			content, ok := txtVal.(string)
			if !ok {
				continue
			}
			lower := strings.ToLower(content)
			if strings.HasPrefix(lower, "v=spf1") &&
				strings.Contains(lower, "all") && !strings.Contains(lower, "-all") {
				warnings.SpfIssues = append(warnings.SpfIssues,
					"SPF record uses potentially unsafe qualifier: "+content)
			}
			if strings.HasPrefix(lower, "v=dmarc1") && strings.Contains(lower, "p=none") {
				warnings.DmarcIssues = append(warnings.DmarcIssues,
					"DMARC policy set to 'none' (monitoring only): "+content)
			}
			for _, pattern := range suspiciousPatterns {
				if strings.Contains(lower, pattern) {
					warnings.SuspiciousText = append(
						warnings.SuspiciousText,
						fmt.Sprintf(
							"Suspicious pattern '%s' found in TXT record: %s",
							pattern,
							content,
						),
					)
					break
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

func collectSensitiveInfoFindings(a ZoneTransferAssessment) []ztFinding {
	var f []ztFinding
	if n := len(a.SensitiveInfo.EmailAddresses); n > 0 {
		f = append(f, ztFinding{
			"Email addresses exposed in zone transfer", "medium",
			fmt.Sprintf(
				"Zone transfer exposed %d email addresses including: %s",
				n,
				joinWithLimit(a.SensitiveInfo.EmailAddresses, 5),
			),
		})
	}
	if n := len(a.SensitiveInfo.Credentials); n > 0 {
		f = append(f, ztFinding{
			"Credentials exposed in zone transfer", "critical",
			fmt.Sprintf("Zone transfer exposed %d possible credentials or secrets", n),
		})
	}
	if n := len(a.SensitiveInfo.ApiKeys); n > 0 {
		f = append(f, ztFinding{
			"API keys exposed in zone transfer", "critical",
			fmt.Sprintf("Zone transfer exposed %d possible API keys or tokens", n),
		})
	}
	if n := len(a.SensitiveInfo.InternalHosts); n > 0 {
		f = append(f, ztFinding{
			"Internal hostnames exposed in zone transfer", "medium",
			fmt.Sprintf(
				"Zone transfer exposed %d internal hostnames including: %s",
				n,
				joinWithLimit(a.SensitiveInfo.InternalHosts, 5),
			),
		})
	}
	return f
}

func collectInternalExposureFindings(a ZoneTransferAssessment) []ztFinding {
	var f []ztFinding
	if n := len(a.InternalExposure.InternalIPs); n > 0 {
		f = append(f, ztFinding{
			"Internal IP addresses exposed in zone transfer", "high",
			fmt.Sprintf(
				"Zone transfer exposed %d internal IP addresses including: %s",
				n,
				joinWithLimit(a.InternalExposure.InternalIPs, 5),
			),
		})
	}
	if n := len(a.InternalExposure.DevelopmentEnv); n > 0 {
		f = append(f, ztFinding{
			"Development environments exposed in zone transfer", "medium",
			fmt.Sprintf(
				"Zone transfer exposed %d development/test environment hostnames including: %s",
				n,
				joinWithLimit(a.InternalExposure.DevelopmentEnv, 5),
			),
		})
	}
	return f
}

func collectSecurityFlagFindings(a ZoneTransferAssessment) []ztFinding {
	var f []ztFinding
	if n := len(a.SecurityFlags.SpfIssues); n > 0 {
		f = append(f, ztFinding{
			"SPF configuration issues identified", "medium",
			fmt.Sprintf(
				"Zone transfer revealed %d SPF configuration issues: %s",
				n,
				joinWithLimit(a.SecurityFlags.SpfIssues, 3),
			),
		})
	}
	if n := len(a.SecurityFlags.DmarcIssues); n > 0 {
		f = append(f, ztFinding{
			"DMARC configuration issues identified", "medium",
			fmt.Sprintf(
				"Zone transfer revealed %d DMARC configuration issues: %s",
				n,
				joinWithLimit(a.SecurityFlags.DmarcIssues, 3),
			),
		})
	}
	if n := len(a.SecurityFlags.SuspiciousText); n > 0 {
		f = append(f, ztFinding{
			"Suspicious text patterns in DNS records", "medium",
			fmt.Sprintf(
				"Zone transfer revealed %d suspicious text patterns in DNS records that may indicate security issues",
				n,
			),
		})
	}
	return f
}

func joinWithLimit(items []string, maxItems int) string {
	if len(items) <= maxItems {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxItems], ", ") + fmt.Sprintf(", and %d more", len(items)-maxItems)
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
