package dnsrecords

import (
	"strings"

	"golang.org/x/net/idna"
)

// CanonicalizeDomain normalizes a DNS name into a single stable form so that
// case and trailing-dot variants of the same name collapse to one identity.
// DNS names are case-insensitive and the trailing dot is optional, so
// "example.com", "Example.COM." and "example.com." are one name. The result is
// the key used for the (tenant_id, domain_name) continuity guarantee, so it
// MUST be applied at every boundary that stores a domain name.
//
// Internationalized names are converted to their ASCII (punycode) form when
// possible; names IDNA can't process (e.g. underscore service labels like
// _dmarc) fall back to the lowercased, dot-stripped form.
func CanonicalizeDomain(name string) string {
	s := strings.TrimSpace(name)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	if s == "" {
		return ""
	}
	if ascii, err := idna.ToASCII(s); err == nil {
		return ascii
	}
	return s
}
