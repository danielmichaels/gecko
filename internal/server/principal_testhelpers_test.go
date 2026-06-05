package server

import (
	"context"

	"github.com/danielmichaels/gecko/internal/auth"
)

// ctxWithPrincipal injects an authenticated owner principal for the given tenant,
// mimicking what apiAuth does in production so handlers can be called directly in
// integration tests without going through the HTTP middleware stack.
func ctxWithPrincipal(ctx context.Context, tenantID int32) context.Context {
	return context.WithValue(ctx, principalKey, &auth.Principal{
		UserID:   1,
		TenantID: tenantID,
		Role:     "owner",
		Email:    "test@example.com",
	})
}
