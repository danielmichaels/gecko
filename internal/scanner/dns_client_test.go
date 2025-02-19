package scanner

import (
	"fmt"
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
