package identity_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/store/identity"
)

type embeddedSetPassword struct{ identity.SetPassword }

type embeddedTombstone struct{ identity.Tombstone }

func TestValidateRefusesMutationsDeclaredOutsideThePackage(t *testing.T) {
	foreign := []identity.Mutation{
		embeddedSetPassword{identity.SetPassword{Subject: alice, PHC: identity.NewPasswordHash(secretPHC), Reason: identity.RotationPasswordChanged, Keep: keep}},
		embeddedTombstone{identity.Tombstone{Subject: alice}},
		&identity.Tombstone{Subject: alice},
	}
	for _, m := range foreign {
		if err := identity.Validate(m); !errors.Is(err, identity.ErrInvalidMutation) {
			t.Errorf("%T: an embedding wrapper must be refused, got %v", m, err)
		}
		if e := identity.EffectsOf(m); e != (identity.Effects{}) {
			t.Errorf("%T: a foreign mutation must have no effects, got %+v", m, e)
		}
		if out := identity.OutboxFor(m, alice, identity.Identifier{}); out != nil {
			t.Errorf("%T: a foreign mutation must queue nothing, got %d rows", m, len(out))
		}
	}
}

type credentialHolder struct {
	cred identity.PasswordCredential
	set  identity.SetPassword
	cv   identity.CreateVerified
	hash identity.PasswordHash
}

func TestPasswordHashNeverFormatsWhenNested(t *testing.T) {
	h := identity.NewPasswordHash(secretPHC)
	v := credentialHolder{
		cred: identity.PasswordCredential{Subject: alice, PHC: h},
		set:  identity.SetPassword{Subject: alice, PHC: h, Reason: identity.RotationPasswordReset},
		cv:   identity.CreateVerified{PHC: h},
		hash: h,
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, x := range []any{v, &v, []credentialHolder{v}, map[string]credentialHolder{"k": v}} {
			if out := fmt.Sprintf(verb, x); strings.Contains(out, "argon2id") {
				t.Errorf("%T formatted with %s leaks the hash: %s", x, verb, out)
			}
		}
	}
	if h.PHC() != secretPHC || h.IsZero() || !(identity.PasswordHash{}).IsZero() {
		t.Fatal("PasswordHash must keep the encoded hash for the verifier")
	}
}

func TestMarkEmailVerifiedWipesPreVerificationCredentials(t *testing.T) {
	m := identity.MarkEmailVerified{Subject: alice}
	if err := identity.Validate(m); err != nil {
		t.Fatalf("an /email/verify wipe without a new password must be valid: %v", err)
	}
	e := identity.EffectsOf(m)
	if !e.BumpsEpoch || e.Event != identity.EventIdentifierChanged {
		t.Fatalf("the first proof of ownership wipes credentials and must bump the epoch (C-39), got %+v", e)
	}
	old := ident(t, identity.IdentifierEmail, "attacker@example.com")
	out := identity.OutboxFor(m, alice, old)
	if len(out) != len(identity.Components()) {
		t.Fatalf("the wipe must reach every component, got %d rows", len(out))
	}
	for _, it := range out {
		if it.Identifier != identity.IdentifierEmail || !it.Old.IsZero() || it.Keep != (uuid.UUID{}) {
			t.Fatalf("the wipe keeps no session and notifies no previous address, got %+v", it)
		}
	}
	confirm := identity.MarkEmailVerified{Subject: alice, PHC: identity.NewPasswordHash(secretPHC)}
	if err := identity.Validate(confirm); err != nil {
		t.Fatalf("a registration confirm sets the registrant's password in the same wipe: %v", err)
	}
	long := identity.MarkEmailVerified{Subject: alice, PHC: identity.NewPasswordHash(strings.Repeat("x", identity.MaxPHCLen+1))}
	if err := identity.Validate(long); !errors.Is(err, identity.ErrInvalidMutation) {
		t.Fatalf("an unbounded hash must be refused, got %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(verb, confirm); strings.Contains(s, "argon2id") {
			t.Fatalf("MarkEmailVerified formatted with %s leaks the hash: %s", verb, s)
		}
	}
}
