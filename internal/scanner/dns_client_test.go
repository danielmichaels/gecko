package scanner

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func ExampleDNSClient_GetParentZone() {
	client := NewDNSClient()
	parent, _ := client.GetParentZone("example.com")
	fmt.Println(parent)
	// Output: com.
}

func TestDnsFqdn(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "simple domain",
			domain:   "example.com",
			expected: "example.com.",
		},
		{
			name:     "subdomain",
			domain:   "sub.example.com",
			expected: "sub.example.com.",
		},
		{
			name:     "already has trailing dot",
			domain:   "example.com.",
			expected: "example.com.",
		},
		{
			name:     "empty domain",
			domain:   "",
			expected: ".",
		},
		{
			name:     "single label",
			domain:   "localhost",
			expected: "localhost.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dns.Fqdn(tt.domain)
			if result != tt.expected {
				t.Errorf("dns.Fqdn(%q) = %q, want %q", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestParseSOARecord(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		record  string
		want    *SOAResult
		wantErr bool
	}{
		{
			name:   "valid SOA record",
			domain: "example.com",
			record: "ns1.example.com admin.example.com 12345 7200 3600 1209600 3600",
			want: &SOAResult{
				Domain:     "example.com",
				NameServer: "ns1.example.com",
				AdminEmail: "admin.example.com",
				Serial:     12345,
				Refresh:    7200,
				Retry:      3600,
				Expire:     1209600,
				MinimumTTL: 3600,
				IsValid:    true,
			},
		},
		{
			name:    "invalid SOA record format",
			domain:  "example.com",
			record:  "ns1.example.com admin.example.com 12345",
			wantErr: true,
		},
		{
			name:    "empty record",
			domain:  "example.com",
			record:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSOARecord(tt.domain, tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSOARecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSOARecord() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMX(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		record  string
		want    *MXRecord
		wantErr bool
	}{
		{
			name:   "valid MX record",
			domain: "example.com",
			record: "10 mail.example.com",
			want: &MXRecord{
				Domain:     "example.com",
				Target:     "mail.example.com",
				Preference: 10,
			},
		},
		{
			name:    "invalid MX record format",
			domain:  "example.com",
			record:  "mail.example.com",
			wantErr: true,
		},
		{
			name:    "invalid preference value",
			domain:  "example.com",
			record:  "invalid mail mail.example.com",
			wantErr: true,
		},
		{
			name:    "empty record",
			domain:  "example.com",
			record:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMX(tt.domain, tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMX() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseMX() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCAA(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		record  string
		want    *CAAResult
		wantErr bool
	}{
		{
			name:   "valid CAA record",
			domain: "example.com",
			record: "letsencrypt.org 0 issue",
			want: &CAAResult{
				Domain:  "example.com",
				Value:   "letsencrypt.org",
				Flag:    0,
				Tag:     "issue",
				IsValid: true,
			},
		},
		{
			name:   "valid CAA record with non-zero flag",
			domain: "example.com",
			record: "letsencrypt.org 128 issuewild",
			want: &CAAResult{
				Domain:  "example.com",
				Value:   "letsencrypt.org",
				Flag:    128,
				Tag:     "issuewild",
				IsValid: true,
			},
		},
		{
			name:    "invalid CAA record format",
			domain:  "example.com",
			record:  "letsencrypt.org issue",
			wantErr: true,
		},
		{
			name:    "empty record",
			domain:  "example.com",
			record:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCAA(tt.domain, tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCAA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCAA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseA(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		record string
		want   *ARecord
	}{
		{
			name:   "valid A record",
			domain: "example.com",
			record: "192.0.2.1",
			want:   &ARecord{Domain: "example.com", IP: "192.0.2.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseA(tt.domain, tt.record)
			if err != nil {
				t.Errorf("ParseA() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseAAAA(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		record string
		want   *AAAARecord
	}{
		{
			name:   "valid AAAA record",
			domain: "example.com",
			record: "2001:db8::1",
			want:   &AAAARecord{Domain: "example.com", IP: "2001:db8::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAAAA(tt.domain, tt.record)
			if err != nil {
				t.Errorf("ParseAAAA() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseAAAA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCNAME(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		record string
		want   *CNAMERecord
	}{
		{
			name:   "valid CNAME record",
			domain: "www.example.com",
			record: "example.com",
			want:   &CNAMERecord{Domain: "www.example.com", Target: "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCNAME(tt.domain, tt.record)
			if err != nil {
				t.Errorf("ParseCNAME() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCNAME() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTXT(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		record string
		want   *TXTRecord
	}{
		{
			name:   "valid TXT record",
			domain: "example.com",
			record: "v=spf1 include:_spf.example.com ~all",
			want: &TXTRecord{
				Domain:  "example.com",
				Content: "v=spf1 include:_spf.example.com ~all",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTXT(tt.domain, tt.record)
			if err != nil {
				t.Errorf("ParseTXT() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTXT() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseNS(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		record string
		want   *NSRecord
	}{
		{
			name:   "valid NS record",
			domain: "example.com",
			record: "ns1.example.com",
			want:   &NSRecord{Domain: "example.com", NameServer: "ns1.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNS(tt.domain, tt.record)
			if err != nil {
				t.Errorf("ParseNS() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseNS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePTR(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		record string
		want   *PTRRecord
	}{
		{
			name:   "valid PTR record",
			domain: "1.2.3.4.in-addr.arpa",
			record: "host.example.com",
			want:   &PTRRecord{Domain: "1.2.3.4.in-addr.arpa", Target: "host.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePTR(tt.domain, tt.record)
			if err != nil {
				t.Errorf("ParsePTR() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePTR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSRV(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		record  string
		want    *SRVResult
		wantErr bool
	}{
		{
			name:   "valid SRV record",
			domain: "_sip._tcp.example.com",
			record: "sipserver.example.com 5060 10 20",
			want: &SRVResult{
				Domain:   "_sip._tcp.example.com",
				Target:   "sipserver.example.com",
				Port:     5060,
				Weight:   10,
				Priority: 20,
				IsValid:  true,
			},
		},
		{
			name:    "invalid SRV record format",
			domain:  "_sip._tcp.example.com",
			record:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSRV(tt.domain, tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSRV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSRV() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDNSKEY(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		record  string
		want    *DNSKEYResult
		wantErr bool
	}{
		{
			name:   "valid DNSKEY record",
			domain: "blog.cloudflare.com",
			record: `oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA== 256 3 13`,
			want: &DNSKEYResult{
				Domain:    "blog.cloudflare.com",
				PublicKey: `oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==`,
				Flags:     256,
				Protocol:  3,
				Algorithm: 13,
				IsValid:   true,
			},
		},
		{
			name:    "invalid DNSKEY record format",
			domain:  "example.com",
			record:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDNSKEY(tt.domain, tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDNSKEY() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseDNSKEY() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDS(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		record  string
		want    *DSResult
		wantErr bool
	}{
		{
			name:   "valid DS record",
			domain: "example.com",
			record: "60485 13 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A",
			want: &DSResult{
				Domain:     "example.com",
				KeyTag:     60485,
				Algorithm:  13,
				DigestType: 2,
				Digest:     "D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A",
				IsValid:    true,
			},
		},
		{
			name:    "invalid DS record format",
			domain:  "example.com",
			record:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDS(tt.domain, tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseDS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRRSIG(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		record  string
		want    *RRSIGResult
		wantErr bool
	}{
		{
			name:   "valid RRSIG record",
			domain: "blog.cloudflare.com",
			record: `48 13 1 86400 1740582155 1739285855 com. 19718 hDFcFleAwABqYBsDMJhsXZbwYDylR6/BtoeWovtfB1jos44v5C1CDbZngIQ3N5I5wt2YKx7+lefeURpWXh0CaA==`,
			want: &RRSIGResult{
				Domain:      "blog.cloudflare.com",
				TypeCovered: 48, // DNSKEY
				Algorithm:   13,
				Labels:      1,
				OriginalTTL: 86400,
				Expiration:  1740582155,
				Inception:   1739285855,
				KeyTag:      19718,
				SignerName:  "com.",
				Signature:   "hDFcFleAwABqYBsDMJhsXZbwYDylR6/BtoeWovtfB1jos44v5C1CDbZngIQ3N5I5wt2YKx7+lefeURpWXh0CaA==",
				IsValid:     true,
			},
		},
		{
			name:    "invalid RRSIG record format",
			domain:  "example.com",
			record:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRRSIG(tt.domain, tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRRSIG() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRRSIG() = %v, want %v", got, tt.want)
			}
		})
	}
}
