package dnsrecords

import (
	"testing"
)

func TestIsTLD(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		wantIsTLD bool
		wantICANN bool
		wantErr   bool
	}{
		{
			name:      "valid TLD com",
			domain:    "com",
			wantIsTLD: true,
			wantICANN: true,
			wantErr:   false,
		},
		{
			name:      "valid TLD org",
			domain:    "org",
			wantIsTLD: true,
			wantICANN: true,
			wantErr:   false,
		},
		{
			name:      "not a TLD example.com",
			domain:    "example.com",
			wantIsTLD: false,
			wantICANN: true,
			wantErr:   false,
		},
		{
			name:      "private suffix co.uk",
			domain:    "co.uk",
			wantIsTLD: true,
			wantICANN: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsTLD, gotICANN, err := IsTLD(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsTLD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotIsTLD != tt.wantIsTLD {
				t.Errorf("IsTLD() isTLD = %v, want %v", gotIsTLD, tt.wantIsTLD)
			}
			if gotICANN != tt.wantICANN {
				t.Errorf("IsTLD() isICANN = %v, want %v", gotICANN, tt.wantICANN)
			}
		})
	}
}

func TestIsSecondLevelDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		want    bool
		wantErr bool
	}{
		{
			name:    "valid second level domain example.com",
			domain:  "example.com",
			want:    true,
			wantErr: false,
		},
		{
			name:    "not second level domain subdomain.example.com",
			domain:  "subdomain.example.com",
			want:    false,
			wantErr: false,
		},
		{
			name:    "not second level domain co.uk",
			domain:  "co.uk",
			want:    false,
			wantErr: true,
		},
		{
			name:    "valid second level domain example.co.uk",
			domain:  "example.co.uk",
			want:    true,
			wantErr: false,
		},
		{
			name:    "not second level domain blog.example.co.uk",
			domain:  "blog.example.co.uk",
			want:    false,
			wantErr: false,
		},
		{
			name:    "empty domain",
			domain:  "",
			want:    false,
			wantErr: true,
		},
		{
			name:    "invalid domain with spaces",
			domain:  "invalid domain",
			want:    false,
			wantErr: true,
		},
		{
			name:    "single label domain",
			domain:  "localhost",
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsSecondLevelDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsSecondLevelDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsSecondLevelDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestIsSubdomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		want    bool
		wantErr bool
	}{
		{
			name:    "valid subdomain test.example.com",
			domain:  "test.example.com",
			want:    true,
			wantErr: false,
		},
		{
			name:    "multiple level subdomain dev.api.example.com",
			domain:  "dev.api.example.com",
			want:    true,
			wantErr: false,
		},
		{
			name:    "not a subdomain example.com",
			domain:  "example.com",
			want:    false,
			wantErr: false,
		},
		{
			name:    "subdomain with special TLD test.example.co.uk",
			domain:  "test.example.co.uk",
			want:    true,
			wantErr: false,
		},
		{
			name:    "empty domain",
			domain:  "",
			want:    false,
			wantErr: true,
		},
		{
			name:    "domain with trailing dot test.example.com.",
			domain:  "test.example.com.",
			want:    true,
			wantErr: false,
		},
		{
			name:    "unicode subdomain café.example.com",
			domain:  "café.example.com",
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsSubdomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsSubdomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsSubdomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetDomainType(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		wantType string
		wantErr  bool
	}{
		{
			name:     "TLD net",
			domain:   "net",
			wantType: "tld",
			wantErr:  false,
		},
		{
			name:     "TLD edu",
			domain:   "edu",
			wantType: "tld",
			wantErr:  false,
		},
		{
			name:     "second level domain test.net",
			domain:   "test.net",
			wantType: "tld",
			wantErr:  false,
		},
		{
			name:     "second level domain with special TLD company.co.jp",
			domain:   "company.co.jp",
			wantType: "tld",
			wantErr:  false,
		},
		{
			name:     "subdomain with multiple levels staging.dev.company.co.jp",
			domain:   "staging.dev.company.co.jp",
			wantType: "subdomain",
			wantErr:  false,
		},
		{
			name:     "punycode domain xn--80akhbyknj4f.com",
			domain:   "xn--80akhbyknj4f.com",
			wantType: "tld",
			wantErr:  false,
		},
		{
			name:     "numeric domain 123.com",
			domain:   "123.com",
			wantType: "tld",
			wantErr:  false,
		},
		{
			name:     "very long subdomain very-long-subdomain-name-that-is-valid.example.com",
			domain:   "very-long-subdomain-name-that-is-valid.example.com",
			wantType: "subdomain",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, err := GetDomainType(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDomainType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotType != tt.wantType {
				t.Errorf("GetDomainType() = %v, want %v", gotType, tt.wantType)
			}
		})
	}
}
