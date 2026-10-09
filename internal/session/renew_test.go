package session_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/session"
)

var errStore = errors.New("store down")

type fakeAuthority struct {
	state    core.AccountState
	mfa      []core.Factor
	stateErr error
}

func (f *fakeAuthority) AccountState(context.Context, core.Subject) (core.AccountState, error) {
	return f.state, f.stateErr
}

func (f *fakeAuthority) MFADecision(context.Context, core.Subject) (core.MFADecision, error) {
	return core.NewMFADecision(f.mfa), nil
}

type fakeClaims struct {
	raw []byte
	err error
}

func (f *fakeClaims) ClaimsFor(context.Context, core.Subject) ([]byte, error) { return f.raw, f.err }

type recorder struct{ got []event.Type }

func (r *recorder) EmitEvent(_ context.Context, e event.Event) { r.got = append(r.got, e.Type) }

func (r *recorder) count(t event.Type) int {
	n := 0
	for _, g := range r.got {
		if g == t {
			n++
		}
	}
	return n
}

var lifetimes = session.Lifetimes{IdleTimeout: time.Hour, MaxLifetime: 12 * time.Hour, RecheckEvery: 5 * time.Minute}

type rig struct {
	clk    *clock.Test
	auth   *fakeAuthority
	claims *fakeClaims
	events *recorder
	r      *session.Renewer
	spec   principaltest.Spec
}

func newRig(t *testing.T) *rig {
	t.Helper()
	start := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	g := &rig{
		clk:    clock.NewTest(start),
		auth:   &fakeAuthority{state: core.NewAccountState(true, false, false, false, true, 3)},
		claims: &fakeClaims{raw: []byte(`{"roles": ["user"]}`)},
		events: &recorder{},
		spec: principaltest.Spec{
			Lineage:         uuid.New(),
			Subject:         core.Subject{User: uuid.New()},
			Factors:         []core.Factor{core.FactorPassword},
			PrimaryAt:       start,
			Epoch:           3,
			Transport:       core.TransportCookies,
			CreatedAt:       start,
			ClaimsFetchedAt: start,
		},
	}
	r, err := session.NewRenewer(session.RenewConfig{Authority: g.auth, Claims: g.claims, Lifetimes: lifetimes, Clock: g.clk.Clock(), Events: g.events})
	if err != nil {
		t.Fatal(err)
	}
	g.r = r
	return g
}

func (g *rig) renew(t *testing.T) (core.SessionAttrs, core.SealedClaims, error) {
	t.Helper()
	return g.r.Renew(t.Context(), principaltest.Attrs(g.spec), core.NewSealedClaims([]byte(`{"roles":["old"]}`)))
}

func TestRenewKeepsSubjectLineageAndFactors(t *testing.T) {
	g := newRig(t)
	g.spec.Factors = []core.Factor{core.FactorPassword, core.FactorTOTP}
	g.spec.SecondAt = g.spec.PrimaryAt
	g.claims.raw = []byte(`{"sub":"` + uuid.NewString() + `","tid":"other","roles":["admin"]}`)
	g.auth.mfa = []core.Factor{core.FactorTOTP}
	g.clk.Advance(lifetimes.RecheckEvery)
	a, c, err := g.renew(t)
	if err != nil {
		t.Fatal(err)
	}
	g.spec.ClaimsFetchedAt = g.clk.Now()
	if !reflect.DeepEqual(a, principaltest.Attrs(g.spec)) {
		t.Fatal("renewal changed more than the claims fetch time")
	}
	if !strings.Contains(string(c.Bytes()), `"roles":["admin"]`) {
		t.Fatalf("claims not refreshed: %s", c.Bytes())
	}
}

func TestRenewEnforcesAccountStateWithoutAnyHook(t *testing.T) {
	cases := map[string]struct {
		state core.AccountState
		mfa   []core.Factor
		want  error
	}{
		"disabled, epoch unchanged": {core.NewAccountState(true, true, false, false, true, 3), nil, core.ErrAccountUnusable},
		"deleted":                   {core.NewAccountState(true, false, true, false, true, 3), nil, core.ErrAccountUnusable},
		"unknown account":           {core.AccountState{}, nil, core.ErrAccountUnusable},
		"epoch moved":               {core.NewAccountState(true, false, false, false, true, 4), nil, core.ErrEpochStale},
		"MFA enrolled since login":  {core.NewAccountState(true, false, false, false, true, 3), []core.Factor{core.FactorTOTP}, core.ErrReauthRequired},
	}
	for name, tc := range cases {
		g := newRig(t)
		g.auth.state, g.auth.mfa = tc.state, tc.mfa
		if _, _, err := g.renew(t); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	g := newRig(t)
	g.auth.stateErr = errStore
	if _, _, err := g.renew(t); !errors.Is(err, errStore) {
		t.Fatalf("authority failure not returned: %v", err)
	}
}

func TestRenewMustChangeOnlyRises(t *testing.T) {
	g := newRig(t)
	g.auth.state = core.NewAccountState(true, false, false, true, true, 3)
	a, _, err := g.renew(t)
	if err != nil || !a.MustChangePassword() {
		t.Fatalf("must-change not raised: %v", err)
	}
	g.spec.MustChange = true
	g.auth.state = core.NewAccountState(true, false, false, false, true, 3)
	a, _, err = g.renew(t)
	if err != nil || !a.MustChangePassword() {
		t.Fatalf("must-change lowered by renewal: %v", err)
	}
}

func TestRenewClaimsPolicy(t *testing.T) {
	t.Run("stale within RecheckEvery", func(t *testing.T) {
		g := newRig(t)
		g.claims.err = errStore
		g.clk.Advance(lifetimes.RecheckEvery)
		a, c, err := g.renew(t)
		if err != nil {
			t.Fatal(err)
		}
		if string(c.Bytes()) != `{"roles":["old"]}` || !a.ClaimsFetchedAt().Equal(g.spec.ClaimsFetchedAt) {
			t.Fatal("stale claims not kept as they were")
		}
		if g.events.count(event.ClaimsStale) != 1 {
			t.Fatal("no ClaimsStale event")
		}
	})
	t.Run("unavailable past RecheckEvery", func(t *testing.T) {
		g := newRig(t)
		g.claims.err = errStore
		g.clk.Advance(lifetimes.RecheckEvery + time.Nanosecond)
		if _, _, err := g.renew(t); !errors.Is(err, core.ErrClaimsUnavailable) || !errors.Is(err, errStore) {
			t.Fatalf("got %v", err)
		}
		if g.events.count(event.ClaimsUnavailable) != 1 {
			t.Fatal("no ClaimsUnavailable event")
		}
	})
	t.Run("malformed claims are a source failure", func(t *testing.T) {
		g := newRig(t)
		g.claims.raw = []byte(`["not","an","object"]`)
		g.clk.Advance(lifetimes.RecheckEvery + time.Second)
		if _, _, err := g.renew(t); !errors.Is(err, core.ErrClaimsUnavailable) || !errors.Is(err, session.ErrMalformedClaims) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unknown subject", func(t *testing.T) {
		g := newRig(t)
		g.claims.err = errors.Join(errors.New("gone"), session.ErrUnknownSubject)
		if _, _, err := g.renew(t); !errors.Is(err, core.ErrClaimsSubjectUnknown) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		g := newRig(t)
		g.claims.raw = []byte(`{"roles":["` + strings.Repeat("r", session.MaxAppClaimsBytes) + `"]}`)
		if _, _, err := g.renew(t); !errors.Is(err, core.ErrClaimsTooLarge) {
			t.Fatalf("got %v", err)
		}
		if g.events.count(event.ClaimsTooLarge) != 1 {
			t.Fatal("no ClaimsTooLarge event")
		}
	})
}

func TestFetchClaimsAtAdmission(t *testing.T) {
	g := newRig(t)
	c, err := g.r.FetchClaims(t.Context(), g.spec.Subject)
	if err != nil || string(c.Bytes()) != `{"roles":["user"]}` {
		t.Fatalf("claims %s, %v: want the compact object", c.Bytes(), err)
	}
	g.claims.err = errStore
	if _, err := g.r.FetchClaims(t.Context(), g.spec.Subject); !errors.Is(err, core.ErrClaimsUnavailable) || g.events.count(event.ClaimsUnavailable) != 1 {
		t.Fatalf("source failure at admission: %v", err)
	}
	g.claims.err = session.ErrUnknownSubject
	if _, err := g.r.FetchClaims(t.Context(), g.spec.Subject); !errors.Is(err, core.ErrClaimsSubjectUnknown) || errors.Is(err, core.ErrClaimsUnavailable) {
		t.Fatalf("unknown subject at admission: %v, want ErrClaimsSubjectUnknown and no outage", err)
	}
	if g.events.count(event.ClaimsUnavailable) != 1 {
		t.Fatal("an unknown subject was reported as a claims outage")
	}
	g.claims.err, g.claims.raw = nil, []byte(`{"r":"`+strings.Repeat("x", session.MaxAppClaimsBytes)+`"}`)
	if _, err := g.r.FetchClaims(t.Context(), g.spec.Subject); !errors.Is(err, core.ErrClaimsTooLarge) || g.events.count(event.ClaimsTooLarge) != 1 {
		t.Fatalf("oversized claims at admission: %v", err)
	}
}

func TestCompactClaims(t *testing.T) {
	c, err := session.CompactClaims([]byte(" {\n \"a\" : [1, 2] } "))
	if err != nil || string(c.Bytes()) != `{"a":[1,2]}` {
		t.Fatalf("%s, %v", c.Bytes(), err)
	}
	for _, bad := range []string{"", "null", "[]", `"x"`, "{", `{"a":1} {}`} {
		if _, err := session.CompactClaims([]byte(bad)); !errors.Is(err, session.ErrMalformedClaims) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	exact := `{"a":"` + strings.Repeat("x", session.MaxAppClaimsBytes-8) + `"}`
	if _, err := session.CompactClaims([]byte(exact)); err != nil {
		t.Fatalf("claims of exactly MaxAppClaimsBytes: %v", err)
	}
	if _, err := session.CompactClaims([]byte(exact[:len(exact)-2] + `x"}`)); !errors.Is(err, core.ErrClaimsTooLarge) {
		t.Fatalf("one byte over: %v", err)
	}
}

func TestNewRenewerValidates(t *testing.T) {
	good := session.RenewConfig{Authority: &fakeAuthority{}, Claims: &fakeClaims{}, Lifetimes: lifetimes}
	bad := map[string]func(c *session.RenewConfig){
		"no authority":         func(c *session.RenewConfig) { c.Authority = nil },
		"no claims":            func(c *session.RenewConfig) { c.Claims = nil },
		"zero recheck":         func(c *session.RenewConfig) { c.Lifetimes.RecheckEvery = 0 },
		"idle over max":        func(c *session.RenewConfig) { c.Lifetimes.IdleTimeout = 13 * time.Hour },
		"negative max":         func(c *session.RenewConfig) { c.Lifetimes.MaxLifetime = -time.Hour },
		"zero lifetimes":       func(c *session.RenewConfig) { c.Lifetimes = session.Lifetimes{} },
		"negative idle":        func(c *session.RenewConfig) { c.Lifetimes.IdleTimeout = -1 },
		"recheck not positive": func(c *session.RenewConfig) { c.Lifetimes.RecheckEvery = -time.Second },
	}
	for name, edit := range bad {
		c := good
		edit(&c)
		if _, err := session.NewRenewer(c); !errors.Is(err, session.ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r, err := session.NewRenewer(good)
	if err != nil || r.Lifetimes() != lifetimes {
		t.Fatalf("%v", err)
	}
	if _, _, err := r.Renew(t.Context(), core.SessionAttrs{}, core.SealedClaims{}); !errors.Is(err, core.ErrInvalidArgument) {
		t.Fatalf("zero attributes: %v", err)
	}
}
