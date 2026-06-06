package dnsclient

import "testing"

func TestNewReturnsResolver(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New() returned a nil DNSClient")
	}
	var _ Resolver = c
}
