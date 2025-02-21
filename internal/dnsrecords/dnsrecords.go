package dnsrecords

import (
	"fmt"
	"github.com/miekg/dns"
	"strconv"
	"strings"
)

type DNSSECResult struct {
	Domain          string
	Status          string
	ValidationError string
	KSKs            []DNSKEYResult
	ZSKs            []DNSKEYResult
	Details         []string
	HasDNSKEY       bool
	HasDS           bool
	HasRRSIG        bool
}
type ZoneTransferResult struct {
	AXFR                  map[string][]dns.RR
	IXFR                  map[string][]dns.RR
	SuccessfulTransfers   map[string]string
	Domain                string
	Error                 string
	NS                    []string
	VulnerableNameservers []string
	Vulnerable            bool
}

func NewZoneTransferResult(domain string) *ZoneTransferResult {
	return &ZoneTransferResult{
		Domain:                domain,
		AXFR:                  make(map[string][]dns.RR),
		IXFR:                  make(map[string][]dns.RR),
		SuccessfulTransfers:   make(map[string]string),
		VulnerableNameservers: make([]string, 0),
	}
}

type ARecord struct {
	Domain string
	IP     string
}

func ParseA(domain, record string) (*ARecord, error) {
	return &ARecord{Domain: domain, IP: record}, nil
}

type AAAARecord struct {
	Domain string
	IP     string
}

func ParseAAAA(domain, record string) (*AAAARecord, error) {
	return &AAAARecord{Domain: domain, IP: record}, nil
}

type CNAMERecord struct {
	Domain string
	Target string
}

func ParseCNAME(domain, record string) (*CNAMERecord, error) {
	return &CNAMERecord{Domain: domain, Target: record}, nil
}

type MXRecord struct {
	Domain     string
	Target     string
	Preference uint16
}

func ParseMX(domain, record string) (*MXRecord, error) {
	parts := strings.Fields(record)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid MX record format")
	}
	pref, _ := strconv.ParseUint(parts[0], 10, 16)
	return &MXRecord{
		Domain:     domain,
		Preference: uint16(pref),
		Target:     parts[1],
	}, nil
}

type TXTRecord struct {
	Domain  string
	Content string
}

func ParseTXT(domain, record string) (*TXTRecord, error) {
	return &TXTRecord{Domain: domain, Content: record}, nil
}

type NSRecord struct {
	Domain     string
	NameServer string
}

func ParseNS(domain, record string) (*NSRecord, error) {
	return &NSRecord{Domain: domain, NameServer: record}, nil
}

type PTRRecord struct {
	Domain string
	Target string
}

func ParsePTR(domain, record string) (*PTRRecord, error) {
	return &PTRRecord{Domain: domain, Target: record}, nil
}

type CAAResult struct {
	Domain      string
	Value       string
	Tag         string
	ErrorReason string
	Flag        uint8
	IsValid     bool
}

func ParseCAA(domain, record string) (*CAAResult, error) {
	parts := strings.Fields(record)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid CAA record format")
	}

	flag, _ := strconv.ParseUint(parts[1], 10, 8)
	value := parts[0]
	if len(parts) > 3 {
		value = strings.Join(parts[3:], " ")
	}

	return &CAAResult{
		Domain:  domain,
		Value:   value,
		Flag:    uint8(flag),
		Tag:     parts[2],
		IsValid: true,
	}, nil
}

type DNSKEYResult struct {
	Domain      string
	PublicKey   string
	ErrorReason string
	Flags       uint16
	Protocol    uint8
	Algorithm   uint8
	IsValid     bool
}

func ParseDNSKEY(domain, record string) (*DNSKEYResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid DNSKEY record format")
	}

	flags, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid Flags: %w", err)
	}
	protocol, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid Protocol: %w", err)
	}
	algorithm, err := strconv.ParseUint(parts[3], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid Algorithm: %w", err)
	}
	result := &DNSKEYResult{
		Domain:    domain,
		PublicKey: parts[0],
		Flags:     uint16(flags),
		Protocol:  uint8(protocol),
		Algorithm: uint8(algorithm),
		IsValid:   true,
	}
	return result, nil
}

type DSResult struct {
	Domain      string
	Digest      string
	ErrorReason string
	KeyTag      uint16
	Algorithm   uint8
	DigestType  uint8
	IsValid     bool
}

func ParseDS(domain, record string) (*DSResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid DS record format")
	}

	keyTag, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid KeyTag: %w", err)
	}
	algorithm, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid Algorithm: %w", err)
	}
	digestType, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid DigestType: %w", err)
	}

	return &DSResult{
		Domain:     domain,
		KeyTag:     uint16(keyTag),
		Algorithm:  uint8(algorithm),
		DigestType: uint8(digestType),
		Digest:     parts[3],
		IsValid:    true,
	}, nil
}

type RRSIGResult struct {
	Domain      string
	SignerName  string
	Signature   string
	OriginalTTL uint32
	Expiration  uint32
	Inception   uint32
	TypeCovered uint16
	KeyTag      uint16
	Algorithm   uint8
	Labels      uint8
	IsValid     bool
}

func ParseRRSIG(domain, record string) (*RRSIGResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 9 {
		return nil, fmt.Errorf("invalid RRSIG record format")
	}

	typeCovered, _ := strconv.ParseUint(parts[0], 10, 16)
	algorithm, _ := strconv.ParseUint(parts[1], 10, 8)
	labels, _ := strconv.ParseUint(parts[2], 10, 8)
	originalTTL, _ := strconv.ParseUint(parts[3], 10, 32)
	expiration, _ := strconv.ParseUint(parts[4], 10, 32)
	inception, _ := strconv.ParseUint(parts[5], 10, 32)
	signerName := parts[6]
	keyTag, _ := strconv.ParseUint(parts[7], 10, 16)

	result := &RRSIGResult{
		Domain:      domain,
		TypeCovered: uint16(typeCovered),
		Algorithm:   uint8(algorithm),
		Labels:      uint8(labels),
		OriginalTTL: uint32(originalTTL),
		Expiration:  uint32(expiration),
		Inception:   uint32(inception),
		KeyTag:      uint16(keyTag),
		SignerName:  signerName,
		Signature:   parts[8],
		IsValid:     true,
	}
	return result, nil
}

type SRVResult struct {
	Domain      string
	Target      string
	ErrorReason string
	Port        uint16
	Weight      uint16
	Priority    uint16
	IsValid     bool
}

func ParseSRV(domain, record string) (*SRVResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid SRV record format")
	}

	port, _ := strconv.ParseUint(parts[1], 10, 16)
	weight, _ := strconv.ParseUint(parts[2], 10, 16)
	priority, _ := strconv.ParseUint(parts[3], 10, 16)

	return &SRVResult{
		Domain:   domain,
		Target:   parts[0],
		Port:     uint16(port),
		Weight:   uint16(weight),
		Priority: uint16(priority),
		IsValid:  true,
	}, nil
}

type SOAResult struct {
	Domain      string
	NameServer  string
	AdminEmail  string
	ErrorReason string
	Serial      uint32
	Refresh     uint32
	Retry       uint32
	Expire      uint32
	MinimumTTL  uint32
	IsValid     bool
}

// ParseSOARecord parses a SOA record string into a SOAResult struct.
//
// The SOA records arrive as a slice of strings, with each string
// representing a field in the SOA record.
func ParseSOARecord(domain, record string) (*SOAResult, error) {
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
		Domain:     domain,
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
