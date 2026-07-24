package service

import (
	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
)

var roleRank = map[string]int{
	string(store.UserRoleViewer):     1,
	string(store.UserRoleManager):    2,
	string(store.UserRoleOwner):      3,
	string(store.UserRoleSuperadmin): 4,
}

func requireRole(p *auth.Principal, roles ...string) error {
	for _, r := range roles {
		if p.Role == r {
			return nil
		}
	}
	return msgErr(ErrForbidden, "insufficient permissions")
}

func OwnerOrManager(p *auth.Principal) bool {
	return requireRole(p, string(store.UserRoleOwner), string(store.UserRoleManager)) == nil
}

func ownerOrManager(p *auth.Principal) error {
	if !OwnerOrManager(p) {
		return msgErr(ErrForbidden, "insufficient permissions")
	}
	return nil
}

func requireCanGrant(p *auth.Principal, targetRole string) error {
	if roleRank[p.Role] < roleRank[targetRole] {
		return msgErr(ErrForbidden, "cannot grant a role above your own")
	}
	return nil
}

func requireCanManage(p *auth.Principal, targetRole string) error {
	if roleRank[p.Role] < roleRank[targetRole] {
		return msgErr(ErrForbidden, "cannot modify a user above your own role")
	}
	return nil
}
