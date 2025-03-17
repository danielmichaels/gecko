package dnsclient

import (
	"fmt"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/dnsrecords"

	"github.com/miekg/dns"
)

func ExampleDNSClient_GetParentZone() {
	client := New()
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
		want    *dnsrecords.SOAResult
		wantErr bool
	}{
		{
			name:   "valid SOA record",
			domain: "example.com",
			record: "ns1.example.com admin.example.com 12345 7200 3600 1209600 3600",
			want: &dnsrecords.SOAResult{
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
			got, err := dnsrecords.ParseSOARecord(tt.domain, tt.record)
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
		want    *dnsrecords.MXRecord
		wantErr bool
	}{
		{
			name:   "valid MX record",
			domain: "example.com",
			record: "10 mail.example.com",
			want: &dnsrecords.MXRecord{
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
			got, err := dnsrecords.ParseMX(tt.domain, tt.record)
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
		want    *dnsrecords.CAAResult
		wantErr bool
	}{
		{
			name:   "valid CAA record",
			domain: "example.com",
			record: "letsencrypt.org 0 issue",
			want: &dnsrecords.CAAResult{
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
			want: &dnsrecords.CAAResult{
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
			got, err := dnsrecords.ParseCAA(tt.domain, tt.record)
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
		want   *dnsrecords.ARecord
	}{
		{
			name:   "valid A record",
			domain: "example.com",
			record: "192.0.2.1",
			want:   &dnsrecords.ARecord{Domain: "example.com", IP: "192.0.2.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsrecords.ParseA(tt.domain, tt.record)
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
		want   *dnsrecords.AAAARecord
	}{
		{
			name:   "valid AAAA record",
			domain: "example.com",
			record: "2001:db8::1",
			want:   &dnsrecords.AAAARecord{Domain: "example.com", IP: "2001:db8::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsrecords.ParseAAAA(tt.domain, tt.record)
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
		want   *dnsrecords.CNAMERecord
	}{
		{
			name:   "valid CNAME record",
			domain: "www.example.com",
			record: "example.com",
			want:   &dnsrecords.CNAMERecord{Domain: "www.example.com", Target: "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsrecords.ParseCNAME(tt.domain, tt.record)
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
		want   *dnsrecords.TXTRecord
	}{
		{
			name:   "valid TXT record",
			domain: "example.com",
			record: "v=spf1 include:_spf.example.com ~all",
			want: &dnsrecords.TXTRecord{
				Domain:  "example.com",
				Content: "v=spf1 include:_spf.example.com ~all",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsrecords.ParseTXT(tt.domain, tt.record)
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
		want   *dnsrecords.NSRecord
	}{
		{
			name:   "valid NS record",
			domain: "example.com",
			record: "ns1.example.com",
			want:   &dnsrecords.NSRecord{Domain: "example.com", NameServer: "ns1.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsrecords.ParseNS(tt.domain, tt.record)
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
		want   *dnsrecords.PTRRecord
	}{
		{
			name:   "valid PTR record",
			domain: "1.2.3.4.in-addr.arpa",
			record: "host.example.com",
			want: &dnsrecords.PTRRecord{
				Domain: "1.2.3.4.in-addr.arpa",
				Target: "host.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnsrecords.ParsePTR(tt.domain, tt.record)
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
		want    *dnsrecords.SRVResult
		wantErr bool
	}{
		{
			name:   "valid SRV record",
			domain: "_sip._tcp.example.com",
			record: "sipserver.example.com 5060 10 20",
			want: &dnsrecords.SRVResult{
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
			got, err := dnsrecords.ParseSRV(tt.domain, tt.record)
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
		want    *dnsrecords.DNSKEYResult
		wantErr bool
	}{
		{
			name:   "valid DNSKEY record",
			domain: "blog.cloudflare.com",
			record: `oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA== 256 3 13`,
			want: &dnsrecords.DNSKEYResult{
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
			got, err := dnsrecords.ParseDNSKEY(tt.domain, tt.record)
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
		want    *dnsrecords.DSResult
		wantErr bool
	}{
		{
			name:   "valid DS record",
			domain: "example.com",
			record: "60485 13 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A",
			want: &dnsrecords.DSResult{
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
			got, err := dnsrecords.ParseDS(tt.domain, tt.record)
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
		want    *dnsrecords.RRSIGResult
		wantErr bool
	}{
		{
			name:   "valid RRSIG record",
			domain: "blog.cloudflare.com",
			record: `48 13 1 86400 1740582155 1739285855 com. 19718 hDFcFleAwABqYBsDMJhsXZbwYDylR6/BtoeWovtfB1jos44v5C1CDbZngIQ3N5I5wt2YKx7+lefeURpWXh0CaA==`,
			want: &dnsrecords.RRSIGResult{
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
			got, err := dnsrecords.ParseRRSIG(tt.domain, tt.record)
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
func TestDNSClient_LookupRecord(t *testing.T) {
	// Create a mock DNS server
	mockServer, err := testhelpers.NewMockDNSServer()
	if err != nil {
		t.Fatalf("Failed to create mock DNS server: %v", err)
	}
	if err := mockServer.Start(); err != nil {
		t.Fatalf("Failed to start mock DNS server: %v", err)
	}
	defer mockServer.Stop()

	// Create a DNS client that uses our mock server
	client := New(
		WithServers([]string{mockServer.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
	)

	// Test cases for different record types
	testCases := []struct {
		name       string
		recordType uint16
		domain     string
		recordData string
		lookupFunc func(string) ([]string, bool)
	}{
		{
			name:       "A record lookup",
			recordType: dns.TypeA,
			domain:     "example.com",
			recordData: "192.0.2.1",
			lookupFunc: client.LookupA,
		},
		{
			name:       "AAAA record lookup",
			recordType: dns.TypeAAAA,
			domain:     "example.com",
			recordData: "2001:db8::1",
			lookupFunc: client.LookupAAAA,
		},
		{
			name:       "CNAME record lookup",
			recordType: dns.TypeCNAME,
			domain:     "www.example.com",
			recordData: "example.com",
			lookupFunc: client.LookupCNAME,
		},
		{
			name:       "MX record lookup",
			recordType: dns.TypeMX,
			domain:     "example.com",
			recordData: "10 mail.example.com",
			lookupFunc: client.LookupMX,
		},
		{
			name:       "TXT record lookup",
			recordType: dns.TypeTXT,
			domain:     "example.com",
			recordData: "v=spf1 include:_spf.google.com -all",
			lookupFunc: client.LookupTXT,
		},
		{
			name:       "NS record lookup",
			recordType: dns.TypeNS,
			domain:     "example.com",
			recordData: "ns1.example.com",
			lookupFunc: client.LookupNS,
		},
		{
			name:       "SOA record lookup",
			recordType: dns.TypeSOA,
			domain:     "example.com",
			recordData: "ns1.example.com hostmaster.example.com 1 7200 3600 1209600 3600",
			lookupFunc: client.LookupSOA,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear previous records
			mockServer.ClearRecords()

			// Add the test record
			err := mockServer.AddRecord(tc.domain, tc.recordType, 3600, tc.recordData)
			if err != nil {
				t.Fatalf("Failed to add record: %v", err)
			}

			// Perform the lookup
			results, ok := tc.lookupFunc(tc.domain)

			// Verify the results
			if !ok {
				t.Errorf("Expected lookup to succeed, but it failed")
			}

			if len(results) == 0 {
				t.Errorf("Expected at least one result, got none")
			} else {
				// For most record types, we can do a simple string comparison
				// For some types like SOA, we might need more complex validation
				found := false
				for _, result := range results {
					// Use contains instead of exact match because formatting might differ
					if strings.Contains(result, strings.Split(tc.recordData, " ")[0]) {
						found = true
						break
					}
				}

				if !found {
					t.Errorf("Expected result containing %q, got %v", tc.recordData, results)
				}
			}
		})
	}
}

func TestDNSClient_LookupNonExistentRecord(t *testing.T) {
	// Create a mock DNS server
	mockServer, err := testhelpers.NewMockDNSServer()
	if err != nil {
		t.Fatalf("Failed to create mock DNS server: %v", err)
	}
	if err := mockServer.Start(); err != nil {
		t.Fatalf("Failed to start mock DNS server: %v", err)
	}
	defer mockServer.Stop()

	// Create a DNS client that uses our mock server
	client := New(
		WithServers([]string{mockServer.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
	)

	// Perform lookup for a domain that doesn't exist
	results, ok := client.LookupA("nonexistent.example.com")

	// Verify the results
	if ok {
		t.Errorf("Expected lookup to fail for non-existent domain, but it succeeded with results: %v", results)
	}

	if len(results) != 0 {
		t.Errorf("Expected empty results for non-existent domain, got: %v", results)
	}
}
func TestDNSClient_GetParentZone(t *testing.T) {
	client := New()

	testCases := []struct {
		domain       string
		expectedZone string
		expectError  bool
	}{
		{"example.com", "com.", false},
		{"sub.example.com", "example.com.", false},
		{"deep.sub.example.com", "sub.example.com.", false},
		{"com", ".", false},
		{".", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.domain, func(t *testing.T) {
			zone, err := client.GetParentZone(tc.domain)

			if tc.expectError && err == nil {
				t.Errorf("Expected error for domain %q, but got none", tc.domain)
			}

			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error for domain %q: %v", tc.domain, err)
			}

			if zone != tc.expectedZone {
				t.Errorf("For domain %q, expected parent zone %q, got %q", tc.domain, tc.expectedZone, zone)
			}
		})
	}
}

func TestDNSClient_WithOptions(t *testing.T) {
	// Test WithServers option
	customServers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	client := New(WithServers(customServers))

	servers := client.GetServers()
	if len(servers) != len(customServers) {
		t.Errorf("Expected %d servers, got %d", len(customServers), len(servers))
	}

	for i, server := range customServers {
		if i < len(servers) && servers[i] != server {
			t.Errorf("Expected server %d to be %q, got %q", i, server, servers[i])
		}
	}

	// Test WithLogger option (can only verify it doesn't crash)
	customLogger := testhelpers.TestLogger
	clientWithLogger := New(WithLogger(customLogger))

	// Just make a simple call to ensure it doesn't crash
	_, _ = clientWithLogger.LookupA("example.com")

	// Test WithClient option
	customDNSClient := &dns.Client{Timeout: 5 * time.Second}
	clientWithCustomDNS := New(WithClient(customDNSClient))

	// Just make a simple call to ensure it doesn't crash
	_, _ = clientWithCustomDNS.LookupA("example.com")
}
