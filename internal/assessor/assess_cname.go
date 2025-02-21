package assessor

import (
	"fmt"
	"time"
)

// DanglingCNAMEAssessmentResult extends AssessmentResultBase for dangling CNAME findings
type DanglingCNAMEAssessmentResult struct {
	AssessmentResultBase
	CNAMERecordName   string `json:"cname_record_name"`
	CNAMETargetDomain string `json:"cname_target_domain"`
	DanglingReason    string `json:"dangling_reason"`
	IsVulnerable      bool   `json:"is_vulnerable"`
}

// GetBaseResult implementation for DanglingCNAMEAssessmentResult
func (r DanglingCNAMEAssessmentResult) GetBaseResult() AssessmentResultBase {
	return r.AssessmentResultBase
}

func NewDanglingCNAMEAssessmentResult(domain, reason string, cnameRecord, cnameTarget string, isVuln bool) *DanglingCNAMEAssessmentResult {
	return &DanglingCNAMEAssessmentResult{
		AssessmentResultBase: AssessmentResultBase{
			Domain:       domain,
			AssessorType: "DanglingCNAMEAssessor",
			Timestamp:    time.Now(),
			Severity:     severityFromVulnerability(isVuln),
			Message:      generateDanglingCNAMEMessage(reason, cnameRecord, cnameTarget),
		},
		CNAMERecordName:   cnameRecord,
		CNAMETargetDomain: cnameTarget,
		DanglingReason:    reason,
		IsVulnerable:      isVuln,
	}
}
func severityFromVulnerability(isVuln bool) string {
	if isVuln {
		return "High"
	}
	return "Info"
}
func generateDanglingCNAMEMessage(reason string, cnameRecord, cnameTarget string) string {
	return fmt.Sprintf("Potential Dangling CNAME Vulnerability: CNAME Record '%s' pointing to target domain '%s' is considered dangling because: %s. Subdomain takeover risk exists.", cnameRecord, cnameTarget, reason)
}
func (a *Assess) AssessCNAMEDangling(domain string) *DanglingCNAMEAssessmentResult {
	a.logger.Warn("CNAME assessment", "status", "not implemented", "domain", domain)
	return nil
}

// todo
// CNAME loop
// CNAME branching chain
// CNAME points at IP
