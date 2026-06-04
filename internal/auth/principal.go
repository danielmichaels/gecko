package auth

// Principal is the authenticated identity attached to a request, independent of
// how it was authenticated (local password, API key, or — later — OIDC). Handlers
// read it to scope every query to the caller's tenant.
type Principal struct {
	UserID   int32
	TenantID int32
	Role     string
	Email    string
}
