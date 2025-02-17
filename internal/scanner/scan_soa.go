package scanner

import (
	"fmt"
	"strconv"
	"strings"
)

type SOAResult struct {
	Domain      string
	NameServer  string
	AdminEmail  string
	Serial      uint32
	Refresh     uint32
	Retry       uint32
	Expire      uint32
	MinimumTTL  uint32
	IsValid     bool
	ErrorReason string
}

func ScanSOA(domain string) *SOAResult {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	dc := NewDNSClient()
	records, ok := dc.LookupSOA(domain)
	if !ok || len(records) == 0 {
		return &SOAResult{
			Domain:      domain,
			IsValid:     false,
			ErrorReason: "SOA record not found",
		}
	}
	result, err := parseSOARecord(records[0])
	if err != nil {
		return &SOAResult{
			Domain:      domain,
			IsValid:     false,
			ErrorReason: err.Error(),
		}
	}

	result.Domain = domain
	return result
}

// parseSOARecord parses a SOA record string into a SOAResult struct.
//
// The SOA records arrive as a slice of strings, with each string
// representing a field in the SOA record.
func parseSOARecord(record string) (*SOAResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 7 {
		return nil, fmt.Errorf("invalid SOA record format")
	}

	serial, _ := strconv.ParseUint(parts[2], 10, 32)
	refresh, _ := strconv.ParseUint(parts[3], 10, 32)
	retry, _ := strconv.ParseUint(parts[4], 10, 32)
	expire, _ := strconv.ParseUint(parts[5], 10, 32)
	minTTL, _ := strconv.ParseUint(parts[6], 10, 32)

	return &SOAResult{
		NameServer: parts[0],
		AdminEmail: parts[1],
		Serial:     uint32(serial),
		Refresh:    uint32(refresh),
		Retry:      uint32(retry),
		Expire:     uint32(expire),
		MinimumTTL: uint32(minTTL),
		IsValid:    true,
	}, nil
}
