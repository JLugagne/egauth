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

	t.Run("zero-value Actor is human", func(t *testing.T) {
		var a egauth.Actor
		if !a.IsHuman() {
			t.Error("zero-value Actor.IsHuman() = false, want true")
		}
		if a.IsMachine() {
			t.Error("zero-value Actor.IsMachine() = true, want false")
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
	})

	t.Run("IsHuman and IsMachine are mutually exclusive for all defined kinds", func(t *testing.T) {
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
