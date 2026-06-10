package service

import (
	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
)

// roleRank orders roles by privilege; a higher number outranks a lower one. An
// unknown role ranks 0, so the grant check below fails closed for it. superadmin
// is included to outrank owner even though the API never assigns it.
var roleRank = map[string]int{
	string(store.UserRoleViewer):     1,
	string(store.UserRoleManager):    2,
	string(store.UserRoleOwner):      3,
	string(store.UserRoleSuperadmin): 4,
}

// requireRole returns ErrForbidden unless p holds one of the given roles.
func requireRole(p *auth.Principal, roles ...string) error {
	for _, r := range roles {
		if p.Role == r {
			return nil
		}
	}
	return msgErr(ErrForbidden, "insufficient permissions")
}

// OwnerOrManager reports whether p may perform owner/manager-gated actions. It is
// the single source of truth for that boundary: the ownerOrManager guard derives
// from it (API enforcement) and the UI derives control visibility from it, so the
// two surfaces cannot drift.
func OwnerOrManager(p *auth.Principal) bool {
	return requireRole(p, string(store.UserRoleOwner), string(store.UserRoleManager)) == nil
}

// ownerOrManager gates an action to owners and managers.
func ownerOrManager(p *auth.Principal) error {
	if !OwnerOrManager(p) {
		return msgErr(ErrForbidden, "insufficient permissions")
	}
	return nil
}

// requireCanGrant returns ErrForbidden unless p may assign targetRole — an actor
// can never grant a role above their own. This caps promotion and closes
// manager→owner escalation (including self-promotion).
func requireCanGrant(p *auth.Principal, targetRole string) error {
	if roleRank[p.Role] < roleRank[targetRole] {
		return msgErr(ErrForbidden, "cannot grant a role above your own")
	}
	return nil
}

// requireCanManage returns ErrForbidden unless p outranks-or-equals targetRole.
// requireCanGrant guards the role being set; this guards the user being acted on,
// so a manager cannot demote, rewrite, or delete an owner.
func requireCanManage(p *auth.Principal, targetRole string) error {
	if roleRank[p.Role] < roleRank[targetRole] {
		return msgErr(ErrForbidden, "cannot modify a user above your own role")
	}
	return nil
}
