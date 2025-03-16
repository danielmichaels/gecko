package testhelpers

import (
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/miekg/dns"
	"strings"
	"testing"
	"time"
)

func TestDNSClient_WithMockServer(t *testing.T) {
	// Create a mock DNS server
	mockServer, err := NewMockDNSServer()
	if err != nil {
		t.Fatalf("Failed to create mock DNS server: %v", err)
	}
	mockServer.Logger = TestLogger

	// Start the server
	if err := mockServer.Start(); err != nil {
		t.Fatalf("Failed to start mock DNS server: %v", err)
	}
	defer mockServer.Stop()

	// Add test records
	testDomain := "example.com"

	// Add A record
	err = mockServer.AddRecord(testDomain, dns.TypeA, 3600, "192.0.2.1")
	if err != nil {
		t.Fatalf("Failed to add A record: %v", err)
	}

	// Add CNAME record
	err = mockServer.AddRecord("www."+testDomain, dns.TypeCNAME, 3600, testDomain)
	if err != nil {
		t.Fatalf("Failed to add CNAME record: %v", err)
	}

	// Add TXT record (SPF)
	err = mockServer.AddRecord(testDomain, dns.TypeTXT, 3600, "v=spf1 include:_spf.google.com -all")
	if err != nil {
		t.Fatalf("Failed to add TXT record: %v", err)
	}

	// Add DKIM record
	dkimSelector := "selector1._domainkey." + testDomain
	dkimValue := "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5oIUrFDn1OuSWCmZ8Ac8IgLaoFR64YP+zRERlH7XiANVAJQGgwIexnbZ1xNDt+1DgXWfSALZnTcXLwX7tJP8wZBzpwrKXJjxPMXIAXCNXNzo/fe8CnWKjnPSxUVLW/QYa4AlNzL/DS8QEJKfqSxZTN5kT7VWvuXsj+8wPnGdFKrwOxkgDqzFASIyjON3JOCWPfhEYzGdnQl3z0Njx7cVpzQzSaQkySVBJZUkGYbpT0UQbPQni7TFbtsWNgZ9nA2ZUJe0D/xhAsepHhRi6KCaNFmh/FgA0jV/xuxsBY/RQUbrHUfV/nDr8aLI+Sh2IaXaIh+FFAPGY6TJJbRkwIDAQAB"
	err = mockServer.AddRecord(dkimSelector, dns.TypeTXT, 3600, dkimValue)
	if err != nil {
		t.Fatalf("Failed to add DKIM record: %v", err)
	}
	// Create a DNS client with shorter timeouts for testing
	testDnsClient := &dns.Client{
		Net:          "udp",
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}
	// Create a DNS client that uses our mock server
	client := dnsclient.New(
		dnsclient.WithServers([]string{mockServer.ListenAddr}),
		dnsclient.WithLogger(TestLogger),
		dnsclient.WithClient(testDnsClient),
	)

	// Test A record lookup
	aRecords, ok := client.LookupA(testDomain)
	if !ok {
		t.Errorf("LookupA failed for %s", testDomain)
	}
	if len(aRecords) != 1 || aRecords[0] != "192.0.2.1" {
		t.Errorf("Expected A record '192.0.2.1', got %v", aRecords)
	}

	// Test CNAME record lookup
	cnameRecords, ok := client.LookupCNAME("www." + testDomain)
	if !ok {
		t.Errorf("LookupCNAME failed for www.%s", testDomain)
	}
	if len(cnameRecords) != 1 || cnameRecords[0] != dns.Fqdn(testDomain) {
		t.Errorf("Expected CNAME record '%s', got %v", dns.Fqdn(testDomain), cnameRecords)
	}

	// Test TXT record lookup (SPF)
	txtRecords, ok := client.LookupTXT(testDomain)
	if !ok {
		t.Errorf("LookupTXT failed for %s", testDomain)
	}
	if len(txtRecords) != 1 || txtRecords[0] != "v=spf1 include:_spf.google.com -all" {
		t.Errorf("Expected TXT record 'v=spf1 include:_spf.google.com -all', got %v", txtRecords)
	}

	// Test DKIM record lookup
	dkimRecords, ok := client.LookupTXT(dkimSelector)
	if !ok {
		t.Errorf("LookupTXT failed for %s", dkimSelector)
	} else {
		// Normalize the expected and actual values by removing all whitespace
		expectedDKIM := strings.ReplaceAll(dkimValue, " ", "")
		actualDKIM := ""
		if len(dkimRecords) > 0 {
			actualDKIM = strings.ReplaceAll(dkimRecords[0], " ", "")
		}

		if actualDKIM != expectedDKIM {
			t.Errorf("Expected DKIM record '%s', got '%s'", expectedDKIM, actualDKIM)
		}
	}
}
