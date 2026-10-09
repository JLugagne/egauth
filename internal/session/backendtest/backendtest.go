// Package backendtest is the G21 suite of DESIGN §9.3 that every session.Backend runs at the
// backend level: Run(t, newBackend). The Protect and ResourceServer checks that need the whole
// composition live in internal/journeytest.
//
// newBackend builds the backend under test from a Fixture it obtains with NewFixture(t): the
// fixture's clock, lifetimes, claims source, MFA enrollment, event sink and revocation outage
// switch are the suite's, and the factory adds what only it can provide (the identity store the
// backend reads, Start and Reissue, which only issuance may call in library code, the revocation
// poll, forged credentials and the Bearer credential carrier).
package backendtest

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store/identity"
)

// Policy returns the lifetimes every backend under test must be built with.
func Policy() session.Lifetimes {
	return session.Lifetimes{IdleTimeout: time.Hour, MaxLifetime: 12 * time.Hour, RecheckEvery: 5 * time.Minute}
}

// StartFunc is Backend.Start of the backend under test.
type StartFunc func(ctx context.Context, w http.ResponseWriter, a core.SessionAttrs, c core.SealedClaims) error

// ReissueFunc is Backend.Reissue of the backend under test.
type ReissueFunc func(ctx context.Context, w http.ResponseWriter, cur session.Handle, a core.SessionAttrs) error

// PollFunc reads the change feed of every revocation cache the backend consults, once.
type PollFunc func(ctx context.Context) error

// Forgery names a credential the suite asks the factory to forge from a valid one.
type Forgery uint8

const (
	// ForgeLegacy is a v0.16-shaped token (no egv, att or typ) for the same subject, signed with
	// the deployment's real key.
	ForgeLegacy Forgery = iota + 1
	// ForgeRandomFamily is a token identical to the valid one but naming a random session id,
	// signed with the deployment's real key.
	ForgeRandomFamily
	// ForgeOtherTransport presents every valid credential, refresh credential included, on the
	// other transport: a cookie session's in headers, or a Bearer session's in cookies.
	ForgeOtherTransport
)

// Credentials are what a client presents: its cookies and its request headers.
type Credentials struct {
	Cookies []*http.Cookie
	Header  http.Header
}

// Forger returns the forgery f of the valid credentials c. Only ForgeOtherTransport keeps a refresh
// credential.
type Forger func(t *testing.T, f Forgery, c Credentials) Credentials

// CarryFunc copies the Bearer credentials a response carries onto the headers of the next
// request.
type CarryFunc func(resp http.Header, next http.Header)

// Fixture is shared by the suite and the backend under test. NewFixture fills the suite's half;
// the factory passed to Run sets Identity, Start, Reissue, Poll, Forge and Carry before it
// returns the backend, which must read Clock, Claims, Enrollment and Events and consult its
// revocation sources through Outage.
//
// StableCredentials declares a backend whose credential survives renewal and changes only on
// Reissue, and that reads its session store on every request (the stateful backend): the reuse
// and rotation-race cases then assert that the credential is kept and that ending the session
// refuses every copy of it at once. The zero value expects rotating refresh credentials with reuse
// detection (the JWT backend).
type Fixture struct {
	Clock             *clock.Test
	Lifetimes         session.Lifetimes
	Claims            *Claims
	Enrollment        *Enrollment
	Events            *Events
	Outage            *Outage
	Identity          identity.Store
	Start             StartFunc
	Reissue           ReissueFunc
	Poll              PollFunc
	Forge             Forger
	Carry             CarryFunc
	StableCredentials bool
}

var fixtures sync.Map

// NewFixture returns the fixture of the suite case t, with a test clock stopped on a whole second
// and the lifetimes of Policy. Call it once per case, from the factory passed to Run.
func NewFixture(t *testing.T) *Fixture {
	t.Helper()
	fx := &Fixture{
		Clock:      clock.NewTest(time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)),
		Lifetimes:  Policy(),
		Claims:     NewClaims(),
		Enrollment: NewEnrollment(),
		Events:     NewEvents(),
		Outage:     &Outage{},
	}
	if _, loaded := fixtures.LoadOrStore(t, fx); loaded {
		t.Fatal("backendtest: NewFixture called twice for one case")
	}
	t.Cleanup(func() { fixtures.Delete(t) })
	return fx
}

func fixtureOf(t *testing.T) *Fixture {
	t.Helper()
	v, ok := fixtures.Load(t)
	if !ok {
		t.Fatal("backendtest: the factory must call NewFixture(t)")
	}
	fx := v.(*Fixture)
	switch {
	case fx.Identity == nil, fx.Start == nil, fx.Reissue == nil, fx.Poll == nil, fx.Forge == nil, fx.Carry == nil:
		t.Fatal("backendtest: the factory must set Identity, Start, Reissue, Poll, Forge and Carry")
	case fx.Lifetimes != Policy():
		t.Fatal("backendtest: the backend must use the lifetimes of Policy()")
	}
	return fx
}

// Run runs every G21 case against a fresh backend built by newBackend for that case.
func Run(t *testing.T, newBackend func(*testing.T) session.Backend) {
	t.Helper()
	for _, c := range cases() {
		t.Run(c.name, func(t *testing.T) {
			b := newBackend(t)
			if b == nil {
				t.Fatal("backendtest: newBackend returned nil")
			}
			c.run(t, newEnv(t, b, fixtureOf(t)))
		})
	}
}
