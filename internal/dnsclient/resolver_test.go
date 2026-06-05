package dnsclient

import "testing"

func TestNewReturnsResolver(t *testing.T) {
	var r Resolver = New()
	if r == nil {
		t.Fatal("New() returned a nil Resolver")
	}
}