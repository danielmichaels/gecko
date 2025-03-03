package dnsrecords

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// IsTLD checks if the given domain is a top-level domain (TLD). It returns two boolean values:
// the first indicates whether the domain is a TLD, and the second indicates whether the TLD is
// an ICANN-managed TLD.
func IsTLD(domain string) (bool, bool, error) {
	ps, icann := publicsuffix.PublicSuffix(domain)
	return domain == ps, icann, nil
}

// IsSecondLevelDomain checks if the given domain is a second-level domain
// (directly registered under a TLD, like example.com)
func IsSecondLevelDomain(domain string) (bool, error) {
	effectiveDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return false, err
	}

	// If domain equals its effective domain, it's a second-level domain
	return domain == effectiveDomain, nil
}

// IsSubdomain checks if the given domain is a subdomain (has more levels than
// the second-level domain, like sub.example.com)
func IsSubdomain(domain string) (bool, error) {
	domain = strings.TrimSuffix(domain, ".")

	// Get the effective registered domain (like example.com)
	effectiveDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return false, err
	}

	// If domain is longer than effective domain and contains it as suffix,
	// it's a subdomain
	return domain != effectiveDomain && strings.HasSuffix(domain, effectiveDomain), nil
}

// GetDomainType determines the type of the given domain, returning one of "tld", "subdomain", or "other".
// If the domain is a top-level domain (TLD), it returns "tld". If the domain is a second-level domain
// (directly registered under a TLD), it also returns "tld". If the domain is a subdomain (has more levels
// than the second-level domain), it returns "subdomain". If the domain does not match any of these
// categories, it returns "other".
func GetDomainType(domain string) (string, error) {
	isTLD, _, err := IsTLD(domain)
	if err != nil {
		return "", err
	}

	if isTLD {
		return "tld", nil
	}

	isSecondLevel, err := IsSecondLevelDomain(domain)
	if err != nil {
		return "", err
	}

	if isSecondLevel {
		return "tld", nil
	}

	// is it a subdomain (like sub.example.com)
	isSubdomain, err := IsSubdomain(domain)
	if err != nil {
		return "", err
	}

	if isSubdomain {
		return "subdomain", nil
	}
	return "other", nil
}
