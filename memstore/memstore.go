// Package memstore assembles every in-memory store, and the memory limiter, into an egauth.Storage
// for tests, examples and single-instance development. Nothing it holds survives a restart or is
// shared between instances, so egauth.New refuses it on a public origin unless the configuration
// acknowledges Insecure.EphemeralState.
package memstore

import (
	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/kek"
	ceremony "github.com/JLugagne/egauth/store/ceremony/memory"
	deployment "github.com/JLugagne/egauth/store/deployment/memory"
	federation "github.com/JLugagne/egauth/store/federation/memory"
	identity "github.com/JLugagne/egauth/store/identity/memory"
	keys "github.com/JLugagne/egauth/store/keys/memory"
	limiter "github.com/JLugagne/egauth/store/limiter/memory"
	mfa "github.com/JLugagne/egauth/store/mfa/memory"
	passkey "github.com/JLugagne/egauth/store/passkey/memory"
	sessions "github.com/JLugagne/egauth/store/sessions/memory"
	tokens "github.com/JLugagne/egauth/store/tokens/memory"
)

// New returns a Storage with every field set, each store empty and Ephemeral. The federation store
// reads its links from the returned identity store, so the two must stay together. The memory
// stores seal nothing at rest, so the KEK is not retained; it is a parameter so that call sites read like
// the persistent assembly and a nil KEK is caught at egauth.New through Config.KEK.
func New(_ kek.KEK) egauth.Storage {
	id := identity.New()
	return egauth.Storage{
		Identity:   id,
		Ceremonies: ceremony.New(),
		Deployment: deployment.New(),
		Limiter:    limiter.New(),
		Tokens:     tokens.New(),
		Sessions:   sessions.New(),
		MFA:        mfa.New(),
		Passkeys:   passkey.New(),
		Federation: federation.New(id),
		Keys:       keys.New(),
	}
}

// NewWithClock is New with every clock-reading store, and the limiter, reading c instead of the
// wall clock, so that expiry and refill follow a test clock; pass egauthtest.Clock.Library. The
// passkey store reads no clock. The zero TestClock reads the wall clock, which makes it New.
func NewWithClock(_ kek.KEK, c egauth.TestClock) egauth.Storage {
	id := identity.NewWithClock(c)
	return egauth.Storage{
		Identity:   id,
		Ceremonies: ceremony.NewWithClock(c),
		Deployment: deployment.NewWithClock(c),
		Limiter:    limiter.NewWithClock(c),
		Tokens:     tokens.NewWithClock(c),
		Sessions:   sessions.NewWithClock(c),
		MFA:        mfa.NewWithClock(c),
		Passkeys:   passkey.New(),
		Federation: federation.NewWithClock(c, id),
		Keys:       keys.NewWithClock(c),
	}
}
