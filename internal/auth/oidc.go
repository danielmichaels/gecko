package auth

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned by the OIDC provider seam until OIDC is built.
var ErrNotImplemented = errors.New("oidc provider not implemented")

// oidcProvider is the seam for OpenID Connect single sign-on. A real implementation
// will verify an ID token via discovery and auto-provision the tenant/user on first
// login — with no handler changes, since it satisfies the same Provider interface.
type oidcProvider struct{}

func newOIDCProvider() *oidcProvider { return &oidcProvider{} }

func (p *oidcProvider) Name() string { return "oidc" }

func (p *oidcProvider) Authenticate(_ context.Context, _ Credentials) (*Principal, error) {
	return nil, ErrNotImplemented
}
