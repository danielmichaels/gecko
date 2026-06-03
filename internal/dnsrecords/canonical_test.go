package dnsrecords

import "testing"

func TestCanonicalizeDomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "example.com", "example.com"},
		{"uppercase", "Example.COM", "example.com"},
		{"trailing dot", "example.com.", "example.com"},
		{"uppercase and trailing dot", "EXAMPLE.com.", "example.com"},
		{"surrounding whitespace", "  example.com  ", "example.com"},
		{"subdomain", "WWW.Example.Com.", "www.example.com"},
		{"internationalized to punycode", "münchen.de", "xn--mnchen-3ya.de"},
		{"underscore service label preserved", "_dmarc.Example.com", "_dmarc.example.com"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanonicalizeDomain(tt.in); got != tt.want {
				t.Errorf("CanonicalizeDomain(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
