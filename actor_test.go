package egauth_test

import (
	"testing"

	egauth "github.com/JLugagne/egauth"
	"github.com/google/uuid"
)

// TestActorKind verifies PrincipalKind constants, IsHuman, IsMachine, and correct zero-value
// behaviour.
func TestActorKind(t *testing.T) {
	t.Run("constants have expected string values", func(t *testing.T) {
		if got := string(egauth.User); got != "user" {
			t.Errorf("User = %q, want %q", got, "user")
		}
		if got := string(egauth.PAT); got != "pat" {
			t.Errorf("PAT = %q, want %q", got, "pat")
		}
		if got := string(egauth.Service); got != "service" {
			t.Errorf("Service = %q, want %q", got, "service")
		}
	})

	t.Run("zero-value Actor is anonymous and not human", func(t *testing.T) {
		var a egauth.Actor
		if a.IsHuman() {
			t.Error("zero-value Actor.IsHuman() = true, want false")
		}
		if a.IsMachine() {
			t.Error("zero-value Actor.IsMachine() = true, want false")
		}
		if !a.IsAnonymous() {
			t.Error("zero-value Actor.IsAnonymous() = false, want true")
		}
	})

	t.Run("User kind is human, not machine", func(t *testing.T) {
		a := egauth.Actor{
			UserID:   uuid.New(),
			TenantID: "t1",
			Kind:     egauth.User,
		}
		if !a.IsHuman() {
			t.Errorf("User actor IsHuman() = false, want true")
		}
		if a.IsMachine() {
			t.Errorf("User actor IsMachine() = true, want false")
		}
		if a.IsAnonymous() {
			t.Errorf("User actor IsAnonymous() = true, want false")
		}
	})

	t.Run("User with empty kind but valid UserID is human", func(t *testing.T) {
		a := egauth.Actor{
			UserID:   uuid.New(),
			TenantID: "t1",
		}
		if !a.IsHuman() {
			t.Errorf("actor with valid UserID and empty Kind IsHuman() = false, want true")
		}
		if a.IsMachine() {
			t.Errorf("actor with valid UserID and empty Kind IsMachine() = true, want false")
		}
		if a.IsAnonymous() {
			t.Errorf("actor with valid UserID IsAnonymous() = true, want false")
		}
	})

	t.Run("PAT kind is human, not machine", func(t *testing.T) {
		keyID := uuid.New()
		a := egauth.Actor{
			UserID:   uuid.New(),
			TenantID: "t1",
			Kind:     egauth.PAT,
			KeyID:    keyID,
			Scopes:   []string{"read:data", "write:data"},
		}
		if !a.IsHuman() {
			t.Errorf("PAT actor IsHuman() = false, want true")
		}
		if a.IsMachine() {
			t.Errorf("PAT actor IsMachine() = true, want false")
		}
		if a.IsAnonymous() {
			t.Errorf("PAT actor IsAnonymous() = true, want false")
		}
		if a.KeyID != keyID {
			t.Errorf("PAT actor KeyID = %v, want %v", a.KeyID, keyID)
		}
		if len(a.Scopes) != 2 {
			t.Errorf("PAT actor Scopes len = %d, want 2", len(a.Scopes))
		}
	})

	t.Run("Service kind is machine, not human", func(t *testing.T) {
		keyID := uuid.New()
		a := egauth.Actor{
			TenantID: "t1",
			Kind:     egauth.Service,
			KeyID:    keyID,
			Scopes:   []string{"ingest"},
		}
		if a.IsHuman() {
			t.Errorf("Service actor IsHuman() = true, want false")
		}
		if !a.IsMachine() {
			t.Errorf("Service actor IsMachine() = false, want true")
		}
		if a.IsAnonymous() {
			t.Errorf("Service actor IsAnonymous() = true, want false")
		}
	})

	t.Run("IsHuman and IsMachine are mutually exclusive for authenticated principals", func(t *testing.T) {
		cases := []struct {
			kind    egauth.PrincipalKind
			human   bool
			machine bool
		}{
			{egauth.User, true, false},
			{egauth.PAT, true, false},
			{egauth.Service, false, true},
		}
		for _, tc := range cases {
			a := egauth.Actor{Kind: tc.kind}
			if tc.human {
				a.UserID = uuid.New()
			} else {
				a.KeyID = uuid.New()
			}
			if a.IsHuman() != tc.human {
				t.Errorf("kind %q: IsHuman() = %v, want %v", tc.kind, a.IsHuman(), tc.human)
			}
			if a.IsMachine() != tc.machine {
				t.Errorf("kind %q: IsMachine() = %v, want %v", tc.kind, a.IsMachine(), tc.machine)
			}
			if a.IsHuman() == a.IsMachine() {
				t.Errorf("kind %q: IsHuman() and IsMachine() must not both be %v", tc.kind, a.IsHuman())
			}
		}
	})
}

func TestActorScopeHelpers(t *testing.T) {
	t.Run("HasScope present", func(t *testing.T) {
		a := egauth.Actor{Scopes: []string{"read:data", "write:data"}}
		if !a.HasScope("read:data") {
			t.Error("HasScope(present) = false, want true")
		}
	})

	t.Run("HasScope absent", func(t *testing.T) {
		a := egauth.Actor{Scopes: []string{"read:data"}}
		if a.HasScope("write:data") {
			t.Error("HasScope(absent) = true, want false")
		}
	})

	t.Run("HasScope empty scopes", func(t *testing.T) {
		a := egauth.Actor{}
		if a.HasScope("read:data") {
			t.Error("HasScope on empty Scopes = true, want false")
		}
	})

	t.Run("HasAllScopes all present", func(t *testing.T) {
		a := egauth.Actor{Scopes: []string{"read:data", "write:data", "admin"}}
		if !a.HasAllScopes("read:data", "write:data") {
			t.Error("HasAllScopes(all present) = false, want true")
		}
	})

	t.Run("HasAllScopes superset — actor has more than requested", func(t *testing.T) {
		a := egauth.Actor{Scopes: []string{"read:data", "write:data", "admin"}}
		if !a.HasAllScopes("read:data") {
			t.Error("HasAllScopes(superset) = false, want true")
		}
	})

	t.Run("HasAllScopes one absent", func(t *testing.T) {
		a := egauth.Actor{Scopes: []string{"read:data"}}
		if a.HasAllScopes("read:data", "write:data") {
			t.Error("HasAllScopes(one absent) = true, want false")
		}
	})

	t.Run("HasAllScopes no args — vacuous true", func(t *testing.T) {
		a := egauth.Actor{}
		if !a.HasAllScopes() {
			t.Error("HasAllScopes() with no args = false, want true (vacuous)")
		}
	})

	t.Run("HasAllScopes empty scopes with args", func(t *testing.T) {
		a := egauth.Actor{}
		if a.HasAllScopes("read:data") {
			t.Error("HasAllScopes on empty Scopes with args = true, want false")
		}
	})

	t.Run("HasAnyScope one present", func(t *testing.T) {
		a := egauth.Actor{Scopes: []string{"read:data", "write:data"}}
		if !a.HasAnyScope("write:data", "admin") {
			t.Error("HasAnyScope(one present) = false, want true")
		}
	})

	t.Run("HasAnyScope none present", func(t *testing.T) {
		a := egauth.Actor{Scopes: []string{"read:data"}}
		if a.HasAnyScope("write:data", "admin") {
			t.Error("HasAnyScope(none present) = true, want false")
		}
	})

	t.Run("HasAnyScope no args — always false", func(t *testing.T) {
		a := egauth.Actor{Scopes: []string{"read:data"}}
		if a.HasAnyScope() {
			t.Error("HasAnyScope() with no args = true, want false")
		}
	})

	t.Run("HasAnyScope empty scopes", func(t *testing.T) {
		a := egauth.Actor{}
		if a.HasAnyScope("read:data") {
			t.Error("HasAnyScope on empty Scopes = true, want false")
		}
	})
}

func TestActorIsAnonymous(t *testing.T) {
	t.Run("zero-value actor is anonymous", func(t *testing.T) {
		var a egauth.Actor
		if !a.IsAnonymous() {
			t.Error("zero-value Actor.IsAnonymous() = false, want true")
		}
	})

	t.Run("actor with UserID is not anonymous", func(t *testing.T) {
		a := egauth.Actor{UserID: uuid.New()}
		if a.IsAnonymous() {
			t.Error("Actor with UserID.IsAnonymous() = true, want false")
		}
	})

	t.Run("actor with KeyID is not anonymous", func(t *testing.T) {
		a := egauth.Actor{KeyID: uuid.New()}
		if a.IsAnonymous() {
			t.Error("Actor with KeyID.IsAnonymous() = true, want false")
		}
	})

	t.Run("actor with both UserID and KeyID is not anonymous", func(t *testing.T) {
		a := egauth.Actor{UserID: uuid.New(), KeyID: uuid.New()}
		if a.IsAnonymous() {
			t.Error("Actor with UserID and KeyID.IsAnonymous() = true, want false")
		}
	})

	t.Run("actor with Kind but nil UserID and KeyID is anonymous and not human", func(t *testing.T) {
		a := egauth.Actor{Kind: egauth.User}
		if !a.IsAnonymous() {
			t.Error("Actor with nil UserID and KeyID.IsAnonymous() = false, want true")
		}
		if a.IsHuman() {
			t.Error("Actor with nil UserID.IsHuman() = true, want false")
		}
	})
}

func TestActorRoleHelpers(t *testing.T) {
	t.Run("HasRole present", func(t *testing.T) {
		a := egauth.Actor{Roles: []string{"admin", "billing_manager"}}
		if !a.HasRole("admin") {
			t.Error("HasRole(present) = false, want true")
		}
	})

	t.Run("HasRole absent", func(t *testing.T) {
		a := egauth.Actor{Roles: []string{"admin"}}
		if a.HasRole("billing_manager") {
			t.Error("HasRole(absent) = true, want false")
		}
	})

	t.Run("HasRole empty roles", func(t *testing.T) {
		a := egauth.Actor{}
		if a.HasRole("admin") {
			t.Error("HasRole on empty Roles = true, want false")
		}
	})

	t.Run("HasAllRoles all present", func(t *testing.T) {
		a := egauth.Actor{Roles: []string{"admin", "billing_manager", "viewer"}}
		if !a.HasAllRoles("admin", "billing_manager") {
			t.Error("HasAllRoles(all present) = false, want true")
		}
	})

	t.Run("HasAllRoles superset — actor has more than requested", func(t *testing.T) {
		a := egauth.Actor{Roles: []string{"admin", "billing_manager", "viewer"}}
		if !a.HasAllRoles("admin") {
			t.Error("HasAllRoles(superset) = false, want true")
		}
	})

	t.Run("HasAllRoles one absent", func(t *testing.T) {
		a := egauth.Actor{Roles: []string{"admin"}}
		if a.HasAllRoles("admin", "billing_manager") {
			t.Error("HasAllRoles(one absent) = true, want false")
		}
	})

	t.Run("HasAllRoles no args — vacuous true", func(t *testing.T) {
		a := egauth.Actor{}
		if !a.HasAllRoles() {
			t.Error("HasAllRoles() with no args = false, want true (vacuous)")
		}
	})

	t.Run("HasAllRoles empty roles with args", func(t *testing.T) {
		a := egauth.Actor{}
		if a.HasAllRoles("admin") {
			t.Error("HasAllRoles on empty Roles with args = true, want false")
		}
	})

	t.Run("HasAnyRole one present", func(t *testing.T) {
		a := egauth.Actor{Roles: []string{"admin", "billing_manager"}}
		if !a.HasAnyRole("billing_manager", "support") {
			t.Error("HasAnyRole(one present) = false, want true")
		}
	})

	t.Run("HasAnyRole none present", func(t *testing.T) {
		a := egauth.Actor{Roles: []string{"admin"}}
		if a.HasAnyRole("billing_manager", "support") {
			t.Error("HasAnyRole(none present) = true, want false")
		}
	})

	t.Run("HasAnyRole no args — always false", func(t *testing.T) {
		a := egauth.Actor{Roles: []string{"admin"}}
		if a.HasAnyRole() {
			t.Error("HasAnyRole() with no args = true, want false")
		}
	})

	t.Run("HasAnyRole empty roles", func(t *testing.T) {
		a := egauth.Actor{}
		if a.HasAnyRole("admin") {
			t.Error("HasAnyRole on empty Roles = true, want false")
		}
	})
}

func TestActorGroupHelpers(t *testing.T) {
	t.Run("HasGroup present", func(t *testing.T) {
		a := egauth.Actor{Groups: []string{"engineers", "security"}}
		if !a.HasGroup("engineers") {
			t.Error("HasGroup(present) = false, want true")
		}
	})

	t.Run("HasGroup absent", func(t *testing.T) {
		a := egauth.Actor{Groups: []string{"engineers"}}
		if a.HasGroup("security") {
			t.Error("HasGroup(absent) = true, want false")
		}
	})

	t.Run("HasGroup empty groups", func(t *testing.T) {
		a := egauth.Actor{}
		if a.HasGroup("engineers") {
			t.Error("HasGroup on empty Groups = true, want false")
		}
	})

	t.Run("HasAllGroups all present", func(t *testing.T) {
		a := egauth.Actor{Groups: []string{"engineers", "security", "infra"}}
		if !a.HasAllGroups("engineers", "security") {
			t.Error("HasAllGroups(all present) = false, want true")
		}
	})

	t.Run("HasAllGroups superset — actor has more than requested", func(t *testing.T) {
		a := egauth.Actor{Groups: []string{"engineers", "security", "infra"}}
		if !a.HasAllGroups("engineers") {
			t.Error("HasAllGroups(superset) = false, want true")
		}
	})

	t.Run("HasAllGroups one absent", func(t *testing.T) {
		a := egauth.Actor{Groups: []string{"engineers"}}
		if a.HasAllGroups("engineers", "security") {
			t.Error("HasAllGroups(one absent) = true, want false")
		}
	})

	t.Run("HasAllGroups no args — vacuous true", func(t *testing.T) {
		a := egauth.Actor{}
		if !a.HasAllGroups() {
			t.Error("HasAllGroups() with no args = false, want true (vacuous)")
		}
	})

	t.Run("HasAllGroups empty groups with args", func(t *testing.T) {
		a := egauth.Actor{}
		if a.HasAllGroups("engineers") {
			t.Error("HasAllGroups on empty Groups with args = true, want false")
		}
	})

	t.Run("HasAnyGroup one present", func(t *testing.T) {
		a := egauth.Actor{Groups: []string{"engineers", "security"}}
		if !a.HasAnyGroup("security", "ops") {
			t.Error("HasAnyGroup(one present) = false, want true")
		}
	})

	t.Run("HasAnyGroup none present", func(t *testing.T) {
		a := egauth.Actor{Groups: []string{"engineers"}}
		if a.HasAnyGroup("security", "ops") {
			t.Error("HasAnyGroup(none present) = true, want false")
		}
	})

	t.Run("HasAnyGroup no args — always false", func(t *testing.T) {
		a := egauth.Actor{Groups: []string{"engineers"}}
		if a.HasAnyGroup() {
			t.Error("HasAnyGroup() with no args = true, want false")
		}
	})

	t.Run("HasAnyGroup empty groups", func(t *testing.T) {
		a := egauth.Actor{}
		if a.HasAnyGroup("engineers") {
			t.Error("HasAnyGroup on empty Groups = true, want false")
		}
	})
}
