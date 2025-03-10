package dnsrecords

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
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

// ZoneTransferData represents the result of a DNS zone transfer operation.
// It captures details about the transferred zone, including domain, nameserver, record counts,
// and the actual DNS records retrieved during the transfer.
type ZoneTransferData struct {
	Domain       string           `json:"domain"`
	Nameserver   string           `json:"nameserver"`
	Timestamp    string           `json:"timestamp"`
	RecordCounts RecordCount      `json:"record_counts"`
	Records      RecordCollection `json:"records"`
	Vulnerable   bool             `json:"vulnerable,omitempty"`
	TransferType string           `json:"transfer_type,omitempty"`
	Error        string           `json:"error,omitempty"`
}

// RecordCount represents the count of different types of DNS records in a zone transfer.
// It tracks the number of AXFR (Authoritative Transfer), IXFR (Incremental Transfer),
// and total records retrieved during the transfer.
type RecordCount struct {
	AXFR  int `json:"axfr"`
	IXFR  int `json:"ixfr"`
	Total int `json:"total"`
}

// RecordCollection represents a collection of DNS records categorized by transfer type.
// It contains separate slices for AXFR (Authoritative Transfer) and IXFR (Incremental Transfer) records.
type RecordCollection struct {
	AXFR []SerializedRecord `json:"axfr"`
	IXFR []SerializedRecord `json:"ixfr"`
}

// SerializedRecord represents a DNS record in a format that can be marshaled to JSON
type SerializedRecord struct {
	Type   string         `json:"type"`
	Name   string         `json:"name"`
	TTL    uint32         `json:"ttl"`
	Class  uint16         `json:"class"`
	RRType uint16         `json:"rrtype"`
	Data   map[string]any `json:"data"`
}

// SerializeRecord converts a DNS resource record (RR) into a standardized SerializedRecord
// that can be easily marshaled to JSON. It extracts common header information and
// specific type-dependent data for various DNS record types.
func SerializeRecord(rr dns.RR) SerializedRecord {
	header := rr.Header()
	rec := SerializedRecord{
		Type:   dns.TypeToString[header.Rrtype],
		Name:   header.Name,
		TTL:    header.Ttl,
		Class:  header.Class,
		RRType: header.Rrtype,
		Data:   make(map[string]any),
	}

	// switch over all the possible RR types
	switch record := rr.(type) {
	case *dns.A:
		rec.Data["ip"] = record.A.String()
	case *dns.AAAA:
		rec.Data["ip"] = record.AAAA.String()
	case *dns.CNAME:
		rec.Data["target"] = record.Target
	case *dns.MX:
		rec.Data["preference"] = record.Preference
		rec.Data["mx"] = record.Mx
	case *dns.TXT:
		rec.Data["txt"] = record.Txt
	case *dns.NS:
		rec.Data["ns"] = record.Ns
	case *dns.SOA:
		rec.Data["ns"] = record.Ns
		rec.Data["mbox"] = record.Mbox
		rec.Data["serial"] = record.Serial
		rec.Data["refresh"] = record.Refresh
		rec.Data["retry"] = record.Retry
		rec.Data["expire"] = record.Expire
		rec.Data["minttl"] = record.Minttl
	case *dns.PTR:
		rec.Data["ptr"] = record.Ptr
	case *dns.SRV:
		rec.Data["priority"] = record.Priority
		rec.Data["weight"] = record.Weight
		rec.Data["port"] = record.Port
		rec.Data["target"] = record.Target
	case *dns.CAA:
		rec.Data["flag"] = record.Flag
		rec.Data["tag"] = record.Tag
		rec.Data["value"] = record.Value
	case *dns.DNSKEY:
		rec.Data["flags"] = record.Flags
		rec.Data["protocol"] = record.Protocol
		rec.Data["algorithm"] = record.Algorithm
		rec.Data["publicKey"] = record.PublicKey
	case *dns.DS:
		rec.Data["keyTag"] = record.KeyTag
		rec.Data["algorithm"] = record.Algorithm
		rec.Data["digestType"] = record.DigestType
		rec.Data["digest"] = record.Digest
	case *dns.RRSIG:
		rec.Data["typeCovered"] = record.TypeCovered
		rec.Data["algorithm"] = record.Algorithm
		rec.Data["labels"] = record.Labels
		rec.Data["origTtl"] = record.OrigTtl
		rec.Data["expiration"] = record.Expiration
		rec.Data["inception"] = record.Inception
		rec.Data["keyTag"] = record.KeyTag
		rec.Data["signerName"] = record.SignerName
		rec.Data["signature"] = record.Signature
	case *dns.HINFO:
		rec.Data["cpu"] = record.Cpu
		rec.Data["os"] = record.Os
	case *dns.NAPTR:
		rec.Data["order"] = record.Order
		rec.Data["preference"] = record.Preference
		rec.Data["flags"] = record.Flags
		rec.Data["service"] = record.Service
		rec.Data["regexp"] = record.Regexp
		rec.Data["replacement"] = record.Replacement
	case *dns.SSHFP:
		rec.Data["algorithm"] = record.Algorithm
		rec.Data["type"] = record.Type
		rec.Data["fingerprint"] = record.FingerPrint
	case *dns.TLSA:
		rec.Data["usage"] = record.Usage
		rec.Data["selector"] = record.Selector
		rec.Data["matchingType"] = record.MatchingType
		rec.Data["certificate"] = record.Certificate
	case *dns.DNAME:
		rec.Data["target"] = record.Target
	}
	return rec
}

// FormatResult returns a JSON-formatted representation of zone transfer results for a nameserver
func (z *ZoneTransferResult) FormatResult(nameserver string) (string, error) {
	data := ZoneTransferData{
		Nameserver: nameserver,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		RecordCounts: RecordCount{
			AXFR:  len(z.AXFR[nameserver]),
			IXFR:  len(z.IXFR[nameserver]),
			Total: len(z.AXFR[nameserver]) + len(z.IXFR[nameserver]),
		},
		Records: RecordCollection{},
	}

	for _, record := range z.AXFR[nameserver] {
		data.Records.AXFR = append(data.Records.AXFR, SerializeRecord(record))
	}

	for _, record := range z.IXFR[nameserver] {
		data.Records.IXFR = append(data.Records.IXFR, SerializeRecord(record))
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func (z *ZoneTransferResult) ToAssessmentData() *ZoneTransferData {
	data := &ZoneTransferData{
		Domain:       z.Domain,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Vulnerable:   z.Vulnerable,
		RecordCounts: RecordCount{},
		Records:      RecordCollection{},
	}

	for _, records := range z.AXFR {
		for _, record := range records {
			data.Records.AXFR = append(data.Records.AXFR, SerializeRecord(record))
		}
		data.RecordCounts.AXFR += len(records)
		data.RecordCounts.Total += len(records)
	}

	for _, records := range z.IXFR {
		for _, record := range records {
			data.Records.IXFR = append(data.Records.IXFR, SerializeRecord(record))
		}
		data.RecordCounts.IXFR += len(records)
		data.RecordCounts.Total += len(records)
	}

	return data
}
