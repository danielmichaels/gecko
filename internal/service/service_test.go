package service_test

import (
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/danielmichaels/gecko/internal/service"
)

func TestSentinelErrors_Distinct(t *testing.T) {
	sentinels := []error{
		service.ErrNotFound,
		service.ErrForbidden,
		service.ErrConflict,
		service.ErrUnauthenticated,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel[%d] (%v) should not match sentinel[%d] (%v)", i, a, j, b)
			}
		}
	}
}

func TestSentinelErrors_IsWrapped(t *testing.T) {
	cases := []struct {
		sentinel error
		name     string
	}{
		{service.ErrNotFound, "ErrNotFound"},
		{service.ErrForbidden, "ErrForbidden"},
		{service.ErrConflict, "ErrConflict"},
		{service.ErrUnauthenticated, "ErrUnauthenticated"},
	}

	for _, tc := range cases {
		wrapped := fmt.Errorf("operation failed: %w", tc.sentinel)
		if !errors.Is(wrapped, tc.sentinel) {
			t.Errorf("%s: errors.Is on wrapped error returned false", tc.name)
		}
	}
}

func TestNew_ReturnsNonNil(t *testing.T) {
	log := slog.Default()
	svc := service.New(nil, log, nil, nil, nil)
	if svc == nil {
		t.Fatal("New returned nil")
	}
	if svc.Log != log {
		t.Error("Log not wired correctly")
	}
}
