package detect

import (
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/checks"
)

const CheckMinimumRecordSet = "minimum_record_set"

const (
	IssueInsufficientNameservers = "insufficient_nameservers"
	IssueMissingApexAddress      = "missing_apex_address"
	IssueMissingIPv6             = "missing_ipv6"
	IssueMissingSOA              = "missing_soa"
	IssueSOATimersOutOfRange     = "soa_timers_out_of_range"
	IssueSOASerialFormat         = "soa_serial_format"
	IssueSOAMNameUnresolvable    = "soa_mname_unresolvable"
	IssueSOARNameMalformed       = "soa_rname_malformed"
	IssueMissingMX               = "missing_mx"
)

// MinimumRecordSetEvidence is the collected apex-hygiene state. Each *LookedUp
// flag separates a genuine authoritative absence (a real finding) from a failed
// lookup (emit nothing). Only meaningful when IsApex.
type MinimumRecordSetEvidence struct {
	SOAMName         string   `json:"soa_mname"`
	SOARName         string   `json:"soa_rname"`
	TXTValues        []string `json:"txt_values"`
	SOASerial        int64    `json:"soa_serial"`
	NSCount          int      `json:"ns_count"`
	SOARefresh       int32    `json:"soa_refresh"`
	SOARetry         int32    `json:"soa_retry"`
	SOAExpire        int32    `json:"soa_expire"`
	SOAMinimumTTL    int32    `json:"soa_minimum_ttl"`
	IsApex           bool     `json:"is_apex"`
	NSLookedUp       bool     `json:"ns_looked_up"`
	ALookedUp        bool     `json:"a_looked_up"`
	HasA             bool     `json:"has_a"`
	AAAALookedUp     bool     `json:"aaaa_looked_up"`
	HasAAAA          bool     `json:"has_aaaa"`
	SOALookedUp      bool     `json:"soa_looked_up"`
	SOAPresent       bool     `json:"soa_present"`
	SOAMNameLookedUp bool     `json:"soa_mname_looked_up"`
	SOAMNameResolves bool     `json:"soa_mname_resolves"`
	MXLookedUp       bool     `json:"mx_looked_up"`
	HasMX            bool     `json:"has_mx"`
	HasNullMX        bool     `json:"has_null_mx"`
}

// MinimumRecordSetDetector judges apex zone hygiene. Only runs for apex domains.
type MinimumRecordSetDetector struct {
	MinNameservers int
}

func (MinimumRecordSetDetector) Kind() string                { return CheckMinimumRecordSet }
func (MinimumRecordSetDetector) Scope() checks.EvidenceScope { return checks.SingleAsset }

func (d MinimumRecordSetDetector) Detect(ev MinimumRecordSetEvidence) ([]checks.Finding, error) {
	if !ev.IsApex {
		return nil, nil
	}
	var out []checks.Finding

	if ev.NSLookedUp && ev.NSCount < d.MinNameservers {
		out = append(out, checks.Finding{
			IssueType: IssueInsufficientNameservers,
			Severity:  "high",
			Title:     "Insufficient nameservers",
			Details: fmt.Sprintf(
				"Only %d nameserver(s) published; RFC 2182 recommends at least %d on separate networks",
				ev.NSCount, d.MinNameservers),
		})
	}

	if ev.ALookedUp && ev.AAAALookedUp && !ev.HasA && !ev.HasAAAA {
		out = append(out, checks.Finding{
			IssueType: IssueMissingApexAddress,
			Severity:  "medium",
			Title:     "Apex has no address record",
			Details:   "Apex publishes no A or AAAA record, so it does not resolve to an address",
		})
	}

	if ev.HasA && ev.AAAALookedUp && !ev.HasAAAA {
		out = append(out, checks.Finding{
			IssueType: IssueMissingIPv6,
			Severity:  "info",
			Title:     "Apex missing IPv6 address",
			Details:   "Apex resolves over IPv4 but publishes no AAAA record",
		})
	}

	if ev.SOALookedUp && !ev.SOAPresent {
		out = append(out, checks.Finding{
			IssueType: IssueMissingSOA,
			Severity:  "medium",
			Title:     "Missing SOA record",
			Details:   "No SOA record published at the zone apex",
		})
	}

	if ev.SOAPresent {
		if offenders := soaTimerOffenders(ev); len(offenders) > 0 {
			out = append(out, checks.Finding{
				IssueType: IssueSOATimersOutOfRange,
				Severity:  "low",
				Title:     "SOA timers outside recommended range",
				Details:   "SOA timers outside RFC 1912 recommended ranges: " + strings.Join(offenders, ", "),
			})
		}
		if !serialLooksDateBased(ev.SOASerial) {
			out = append(out, checks.Finding{
				IssueType: IssueSOASerialFormat,
				Severity:  "info",
				Title:     "SOA serial not date-based",
				Details:   fmt.Sprintf("SOA serial %d is not in the advisory date-based YYYYMMDDnn format", ev.SOASerial),
			})
		}
		if ev.SOAMNameLookedUp && !ev.SOAMNameResolves {
			out = append(out, checks.Finding{
				IssueType: IssueSOAMNameUnresolvable,
				Severity:  "medium",
				Title:     "SOA MNAME does not resolve",
				Details:   fmt.Sprintf("SOA MNAME %q does not resolve to an A or AAAA record", ev.SOAMName),
			})
		}
		if !rnameWellFormed(ev.SOARName) {
			out = append(out, checks.Finding{
				IssueType: IssueSOARNameMalformed,
				Severity:  "low",
				Title:     "SOA RNAME malformed",
				Details:   fmt.Sprintf("SOA RNAME %q is not a well-formed responsible-party address", ev.SOARName),
			})
		}
	}

	if ev.MXLookedUp && !ev.HasMX && !ev.HasNullMX && hasEmailIntent(ev.TXTValues) {
		out = append(out, checks.Finding{
			IssueType: IssueMissingMX,
			Severity:  "low",
			Title:     "Missing MX despite email-auth records",
			Details:   "Domain publishes email-authentication records (SPF/DMARC) but no MX or null-MX",
		})
	}

	return out, nil
}

type soaTimerRange struct {
	name   string
	value  int32
	lo, hi int32
}

// soaTimerOffenders returns the RFC 1912 timer violations, formatted for details.
func soaTimerOffenders(ev MinimumRecordSetEvidence) []string {
	ranges := []soaTimerRange{
		{"refresh", ev.SOARefresh, 1200, 86400},
		{"retry", ev.SOARetry, 120, 7200},
		{"expire", ev.SOAExpire, 604800, 2419200},
		{"minimum", ev.SOAMinimumTTL, 300, 86400},
	}
	var offenders []string
	for _, r := range ranges {
		if r.value < r.lo || r.value > r.hi {
			offenders = append(offenders,
				fmt.Sprintf("%s=%d (recommended %d-%d)", r.name, r.value, r.lo, r.hi))
		}
	}
	return offenders
}

// serialLooksDateBased reports whether a SOA serial plausibly follows the advisory
// YYYYMMDDnn convention (RFC 1912).
func serialLooksDateBased(serial int64) bool {
	if serial < 1900010100 || serial > 2999123199 {
		return false
	}
	date := serial / 100
	year := date / 10000
	month := (date / 100) % 100
	day := date % 100
	return year >= 1970 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31
}

// rnameWellFormed reports whether a SOA RNAME converts to a plausible email: a
// non-empty local part and a dotted domain part.
func rnameWellFormed(rname string) bool {
	r := strings.TrimSuffix(strings.TrimSpace(rname), ".")
	if r == "" {
		return false
	}
	dot := strings.Index(r, ".")
	if dot <= 0 || dot == len(r)-1 {
		return false
	}
	local, domain := r[:dot], r[dot+1:]
	return local != "" && strings.Contains(domain, ".")
}

func hasEmailIntent(txt []string) bool {
	for _, t := range txt {
		v := strings.ToLower(t)
		if strings.Contains(v, "v=spf1") || strings.Contains(v, "v=dmarc1") {
			return true
		}
	}
	return false
}
