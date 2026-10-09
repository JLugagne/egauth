package backendtest

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/tokens"
)

const (
	reissueRounds   = 8
	revokeRacers    = 32
	rotationRacers  = 16
	oversizedFiller = session.MaxAppClaimsBytes
)

type suiteCase struct {
	name string
	run  func(t *testing.T, e *env)
}

func cases() []suiteCase {
	return []suiteCase{
		{"PreservesEverySealedFieldAcrossRenewalCookies", func(t *testing.T, e *env) { preserves(e, core.TransportCookies) }},
		{"PreservesEverySealedFieldAcrossRenewalBearer", func(t *testing.T, e *env) { preserves(e, core.TransportBearer) }},
		{"RefusesForgedCredentials", refusesForgeries},
		{"MustChangeOnlyRises", mustChangeOnlyRises},
		{"RefusesUnusableSessionsWithoutAnyHook", refusesUnusable},
		{"RejectsRevokedFamilyWithinPollBound", rejectsRevokedFamily},
		{"RejectsStaleEpochWithDeadPoller", rejectsStaleEpochDeadPoller},
		{"FailsClosedWhileRevocationSourceIsDown", failsClosedOnOutage},
		{"RevokesFamilyOnReuse", revokesOnReuse},
		{"ServesRequestsRacingOneRotation", servesRacingRequests},
		{"ReissueIsAtomicAgainstRevocation", reissueAtomic},
		{"EnforcesAbsoluteLifetime", absoluteLifetime},
		{"EraseTenantEndsSessions", eraseTenant},
		{"SealsTransport", sealsTransport},
		{"AppliesClaimsPolicy", claimsPolicy},
		{"RefusesOversizedClaims", oversizedClaims},
		{"CookieOutlivesServerIdleExpiry", cookieOutlivesIdle},
		{"KeepsSessionIDAcrossReissue", keepsSessionID},
		{"KeptLineageSurvivesRevocationInTheSameSecond", keptLineageSurvives},
		{"RenewedFamilyStaysOwnedByItsSubject", renewedFamilyOwned},
		{"EndRevokesAndIsIdempotent", endRevokes},
		{"ReportsDurability", reportsDurability},
	}
}

func preserves(e *env, tr core.Transport) {
	t := e.t
	s := e.newUser()
	spec := e.fullSpec(s, tr)
	a := principaltest.Attrs(spec)
	c := e.start(a)
	res := c.expect(statusOK, "fresh session")
	e.sameAttrs(res.Attrs(), a, "before renewal")
	if !bytes.Equal(res.Claims().Bytes(), e.fx.Claims.Value().Bytes()) {
		t.Fatalf("claims changed: %s", res.Claims().Bytes())
	}
	family := res.Handle().ID()
	e.fx.Claims.Set([]byte(`{"roles":["admin"]}`))
	e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
	res = c.expect(statusOK, "renewal past RecheckEvery")
	spec.ClaimsFetchedAt = e.now()
	want := principaltest.Attrs(spec)
	e.sameAttrs(res.Attrs(), want, "after renewal")
	if res.Handle().ID() != family || res.Handle().Subject() != s || res.Handle().Lineage() != a.Lineage() {
		t.Fatal("renewal moved the session to another family, subject or lineage")
	}
	if string(res.Claims().Bytes()) != `{"roles":["admin"]}` {
		t.Fatalf("renewal did not refresh the claims: %s", res.Claims().Bytes())
	}
	res = c.expect(statusOK, "renewed credentials")
	e.sameAttrs(res.Attrs(), want, "renewed credentials")
}

func refusesForgeries(t *testing.T, e *env) {
	for _, tr := range []core.Transport{core.TransportCookies, core.TransportBearer} {
		s := e.newUser()
		c := e.start(principaltest.Attrs(e.fullSpec(s, tr)))
		c.expect(statusOK, "genuine session")
		for _, f := range []Forgery{ForgeLegacy, ForgeRandomFamily} {
			forged := e.withCredentials(e.fx.Forge(t, f, c.credentials()))
			forged.expect(statusUnauth, "forgery")
		}
		c.expect(statusOK, "genuine session after forgeries")
	}
}

func mustChangeOnlyRises(t *testing.T, e *env) {
	s := e.newUser()
	c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	e.apply(identity.SetMustChange{Subject: s, MustChange: true})
	e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
	if res := c.expect(statusOK, "renewal after must-change"); !res.Attrs().MustChangePassword() {
		t.Fatal("renewal did not pick up must-change")
	}
	e.apply(identity.SetMustChange{Subject: s, MustChange: false})
	e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
	if res := c.expect(statusOK, "renewal after clearing must-change"); !res.Attrs().MustChangePassword() {
		t.Fatal("renewal cleared must-change: only a password change may")
	}
}

func refusesUnusable(t *testing.T, e *env) {
	mutations := map[string]func(s principal.Subject) identity.Mutation{
		"disabled": func(s principal.Subject) identity.Mutation {
			return identity.SetDisabledState{Subject: s, Disable: true}
		},
		"deleted": func(s principal.Subject) identity.Mutation { return identity.Tombstone{Subject: s} },
		"epoch_stale": func(s principal.Subject) identity.Mutation {
			return identity.BumpEpoch{Subject: s, Change: identity.FactorTOTPEnrolled}
		},
	}
	for name, m := range mutations {
		for _, renewing := range []bool{false, true} {
			s := e.newUser()
			c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
			c.expect(statusOK, name+" before")
			if renewing {
				e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
			}
			e.apply(m(s))
			c.expect(statusUnauth, name)
		}
	}
	s := e.newUser()
	c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	e.fx.Enrollment.Enroll(s, core.FactorTOTP)
	e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
	c.expect(statusUnauth, "single-factor session of a subject enrolled in MFA")
}

func rejectsRevokedFamily(t *testing.T, e *env) {
	end := func(c *client) {
		res := c.expect(statusOK, "live session")
		if err := e.b.OnSessionEnded(t.Context(), lifecycle.SessionEnded{Subject: res.Attrs().Subject(), Family: res.Handle().ID()}); err != nil {
			t.Fatal(err)
		}
	}
	s := e.newUser()
	never := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	end(never)
	never.expect(statusUnauth, "revoked sid, poller never started")

	polled := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	e.poll()
	end(polled)
	e.poll()
	polled.expect(statusUnauth, "revoked sid, live poller")

	dead := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportBearer)))
	e.poll()
	end(dead)
	e.advance(revoke.PollBound)
	dead.expect(statusUnauth, "revoked sid, poller dead for PollBound")
}

func (e *env) poll() {
	e.t.Helper()
	if err := e.fx.Poll(e.t.Context()); err != nil {
		e.t.Fatalf("poll: %v", err)
	}
}

func rejectsStaleEpochDeadPoller(t *testing.T, e *env) {
	s := e.newUser()
	c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	e.poll()
	c.expect(statusOK, "live session")
	e.apply(identity.BumpEpoch{Subject: s, Change: identity.FactorPasskeyAdded})
	e.advance(revoke.PollBound)
	c.expect(statusUnauth, "stale epoch, poller dead for PollBound")
}

func failsClosedOnOutage(t *testing.T, e *env) {
	s := e.newUser()
	c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	e.fx.Outage.Set(true)
	c.expect(statusUnavailable, "revocation source down, never polled")
	e.fx.Outage.Set(false)
	c.expect(statusOK, "revocation source back")

	e.poll()
	c.expect(statusOK, "cached")
	e.fx.Outage.Set(true)
	if err := e.fx.Poll(t.Context()); err == nil {
		t.Fatal("poll succeeded during the outage")
	}
	e.advance(revoke.PollBound)
	c.expect(statusUnavailable, "revocation source down past PollBound")
	e.fx.Outage.Set(false)
	c.expect(statusOK, "first check after recovery")
}

func revokesOnReuse(t *testing.T, e *env) {
	if e.fx.StableCredentials {
		keepsCredentialAcrossRenewal(t, e)
		return
	}
	type scenario struct {
		name      string
		wait      time.Duration
		otherUA   bool
		survivors bool
	}
	for _, sc := range []scenario{
		{name: "outside grace", wait: tokens.ReuseGrace + time.Second},
		{name: "inside grace, other client", wait: time.Second, otherUA: true},
		{name: "inside grace, same client", wait: time.Second, survivors: true},
	} {
		s := e.newUser()
		c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
		e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
		old := c.clone()
		c.expect(statusOK, sc.name+": rotation")
		e.advance(sc.wait)
		if sc.otherUA {
			old.ua = "other-client/2"
		}
		if !sc.survivors {
			old.expect(statusUnauth, sc.name+": replayed refresh token")
			c.expect(statusUnauth, sc.name+": family after reuse")
			continue
		}
		before := old.clone()
		old.expect(statusOK, sc.name+": request racing the rotation")
		if !old.sameCredentials(before) {
			t.Fatal(sc.name + ": a request racing the rotation received new credentials")
		}
		c.expect(statusOK, sc.name+": rotated session")
	}
}

func keepsCredentialAcrossRenewal(t *testing.T, e *env) {
	for _, tr := range []core.Transport{core.TransportCookies, core.TransportBearer} {
		s := e.newUser()
		c := e.start(principaltest.Attrs(e.passwordSpec(s, tr)))
		e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
		old := c.clone()
		res := c.expect(statusOK, "renewal")
		if !c.sameCredentials(old) {
			t.Fatalf("transport %v: renewal changed a credential declared stable", tr)
		}
		e.advance(tokens.ReuseGrace + time.Second)
		old.expect(statusOK, "copy of a stable credential")
		if err := e.b.OnSessionEnded(t.Context(), lifecycle.SessionEnded{Subject: s, Family: res.Handle().ID()}); err != nil {
			t.Fatal(err)
		}
		old.expect(statusUnauth, "copy of an ended session, never polled")
		c.expect(statusUnauth, "ended session, never polled")
	}
}

func servesRacingRequests(t *testing.T, e *env) {
	if e.fx.StableCredentials {
		servesRacingRenewals(t, e)
		return
	}
	for _, tr := range []core.Transport{core.TransportCookies, core.TransportBearer} {
		s := e.newUser()
		c := e.start(principaltest.Attrs(e.passwordSpec(s, tr)))
		e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
		racers := make([]*client, rotationRacers)
		answers := make([]int, rotationRacers)
		for i := range racers {
			racers[i] = c.clone()
		}
		var wg sync.WaitGroup
		gate := make(chan struct{})
		for i, r := range racers {
			wg.Go(func() {
				<-gate
				_, err := r.resume()
				answers[i] = status(err)
			})
		}
		close(gate)
		wg.Wait()
		var winner *client
		for i, r := range racers {
			if answers[i] != statusOK {
				t.Fatalf("transport %v: racer %d answered %d on a live session", tr, i, answers[i])
			}
			if r.sameCredentials(c) {
				continue
			}
			if winner != nil {
				t.Fatalf("transport %v: two racers received new credentials", tr)
			}
			winner = r
		}
		if winner == nil {
			t.Fatalf("transport %v: no racer renewed the session", tr)
		}
		e.advance(tokens.ReuseGrace + time.Second)
		winner.expect(statusOK, "family after a race within ReuseGrace")
	}
}

func servesRacingRenewals(t *testing.T, e *env) {
	for _, tr := range []core.Transport{core.TransportCookies, core.TransportBearer} {
		s := e.newUser()
		c := e.start(principaltest.Attrs(e.passwordSpec(s, tr)))
		e.fx.Claims.Set([]byte(`{"roles":["raced"]}`))
		e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
		racers := make([]*client, rotationRacers)
		answers := make([]int, rotationRacers)
		for i := range racers {
			racers[i] = c.clone()
		}
		var wg sync.WaitGroup
		gate := make(chan struct{})
		for i, r := range racers {
			wg.Go(func() {
				<-gate
				_, err := r.resume()
				answers[i] = status(err)
			})
		}
		close(gate)
		wg.Wait()
		for i, r := range racers {
			if answers[i] != statusOK {
				t.Fatalf("transport %v: racer %d answered %d on a live session", tr, i, answers[i])
			}
			if !r.sameCredentials(c) {
				t.Fatalf("transport %v: racer %d received a new credential", tr, i)
			}
		}
		e.advance(tokens.ReuseGrace + time.Second)
		if res := c.expect(statusOK, "session after racing renewals"); string(res.Claims().Bytes()) != `{"roles":["raced"]}` {
			t.Fatalf("transport %v: racing renewals lost the renewed claims: %s", tr, res.Claims().Bytes())
		}
	}
}

func reissueAtomic(t *testing.T, e *env) {
	for range reissueRounds {
		s := e.newUser()
		a := principaltest.Attrs(e.passwordSpec(s, core.TransportCookies))
		c := e.start(a)
		res := c.expect(statusOK, "session to reissue")
		var (
			wg      sync.WaitGroup
			gate    = make(chan struct{})
			next    *client
			nextErr error
		)
		wg.Add(revokeRacers + 1)
		go func() {
			defer wg.Done()
			<-gate
			next, nextErr = e.reissue(res.Handle(), a)
		}()
		for range revokeRacers {
			go func() {
				defer wg.Done()
				<-gate
				if err := e.b.OnDisabled(t.Context(), lifecycle.AccountEvent{Subject: s}); err != nil {
					t.Error(err)
				}
			}()
		}
		close(gate)
		wg.Wait()
		if nextErr == nil {
			next.expect(statusUnauth, "family reissued during RevokeForSubject")
		} else if status(nextErr) == statusUnavailable {
			t.Fatalf("Reissue failed with an outage: %v", nextErr)
		}
		c.expect(statusUnauth, "family revoked by RevokeForSubject")
	}
}

func absoluteLifetime(t *testing.T, e *env) {
	s := e.newUser()
	spec := e.passwordSpec(s, core.TransportCookies)
	c := e.start(principaltest.Attrs(spec))
	end := spec.CreatedAt.Add(e.fx.Lifetimes.MaxLifetime)
	step := e.fx.Lifetimes.IdleTimeout / 2
	for e.now().Add(step).Before(end) {
		e.advance(step)
		c.expect(statusOK, "within the absolute lifetime")
	}
	e.fx.Clock.Set(end)
	c.expect(statusUnauth, "at the absolute lifetime")
}

func eraseTenant(t *testing.T, e *env) {
	for _, renewing := range []bool{false, true} {
		s := e.newUser()
		c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
		c.expect(statusOK, "before erasure")
		if renewing {
			e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
		}
		if err := e.b.OnTenantErased(t.Context(), lifecycle.TenantErased{Tenant: s.Tenant}); err != nil {
			t.Fatal(err)
		}
		c.expect(statusUnauth, "after EraseTenant")
	}
}

func sealsTransport(t *testing.T, e *env) {
	for _, tr := range []core.Transport{core.TransportCookies, core.TransportBearer} {
		s := e.newUser()
		c := e.start(principaltest.Attrs(e.passwordSpec(s, tr)))
		if res := c.expect(statusOK, "own transport"); res.Attrs().Transport() != tr {
			t.Fatal("transport changed")
		}
		moved := e.withCredentials(e.fx.Forge(t, ForgeOtherTransport, c.credentials()))
		moved.expect(statusUnauth, "credentials on the other transport")
		e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
		moved.expect(statusUnauth, "renewal on the other transport")
		c.expect(statusOK, "renewal on the sealed transport")
	}
}

func claimsPolicy(t *testing.T, e *env) {
	recheck := e.fx.Lifetimes.RecheckEvery
	s := e.newUser()
	c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	before := e.fx.Claims.Value()
	e.fx.Claims.Fail()
	e.advance(recheck)
	res := c.expect(statusOK, "claims source down within RecheckEvery of the last fetch")
	if !bytes.Equal(res.Claims().Bytes(), before.Bytes()) || e.fx.Events.Count(event.ClaimsStale) != 1 {
		t.Fatal("stale claims were not kept for one period with a ClaimsStale event")
	}
	e.advance(recheck)
	c.expect(statusUnavailable, "claims source down past the bound")
	if e.fx.Events.Count(event.ClaimsUnavailable) == 0 {
		t.Fatal("no ClaimsUnavailable event")
	}
	e.fx.Claims.Set([]byte(`{"roles":["back"]}`))
	if res := c.expect(statusOK, "claims source recovered"); string(res.Claims().Bytes()) != `{"roles":["back"]}` {
		t.Fatalf("claims not refreshed after recovery: %s", res.Claims().Bytes())
	}

	u := e.newUser()
	gone := e.start(principaltest.Attrs(e.passwordSpec(u, core.TransportCookies)))
	e.fx.Claims.Forget()
	e.advance(recheck + time.Second)
	gone.expect(statusUnauth, "claims source no longer knows the subject")
	e.fx.Claims.Recover()
	gone.expect(statusUnauth, "session revoked on ErrUnknownSubject")
}

func oversized() []byte {
	return []byte(`{"roles":["` + strings.Repeat("r", oversizedFiller) + `"]}`)
}

func oversizedClaims(t *testing.T, e *env) {
	s := e.newUser()
	if _, err := e.tryStart(principaltest.Attrs(e.passwordSpec(s, core.TransportBearer)), core.NewSealedClaims(oversized())); !errors.Is(err, core.ErrClaimsTooLarge) {
		t.Fatalf("Start accepted oversized claims: %v", err)
	}
	if e.fx.Events.Count(event.ClaimsTooLarge) != 1 {
		t.Fatal("no ClaimsTooLarge event at Start")
	}
	c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportBearer)))
	e.fx.Claims.Set(oversized())
	e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
	if _, err := c.resume(); !errors.Is(err, core.ErrClaimsTooLarge) {
		t.Fatalf("renewal accepted oversized claims: %v", err)
	}
	if e.fx.Events.Count(event.ClaimsTooLarge) != 2 {
		t.Fatal("no ClaimsTooLarge event at renewal")
	}
}

func cookieOutlivesIdle(t *testing.T, e *env) {
	life := e.fx.Lifetimes
	s := e.newUser()
	c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	began := e.now()
	for e.now().Sub(began) <= life.IdleTimeout+life.RecheckEvery {
		e.advance(life.RecheckEvery + 1500*time.Millisecond)
		c.expect(statusOK, "active remembered session")
		idleEnd := e.now().Add(life.IdleTimeout)
		for name, jc := range c.cookies {
			if jc.expires.IsZero() || jc.expires.Before(idleEnd) {
				t.Fatalf("cookie %s expires at %s, before the server idle expiry %s", name, jc.expires, idleEnd)
			}
		}
	}
	e.advance(life.IdleTimeout + time.Second)
	c.expect(statusUnauth, "idle past IdleTimeout")

	spec := e.passwordSpec(s, core.TransportCookies)
	spec.RememberMe = false
	b := e.start(principaltest.Attrs(spec))
	for name, jc := range b.cookies {
		if !jc.expires.IsZero() {
			t.Fatalf("cookie %s of a session that is not remembered has a Max-Age", name)
		}
	}
}

func keepsSessionID(t *testing.T, e *env) {
	s := e.newUser()
	spec := e.fullSpec(s, core.TransportCookies)
	a := principaltest.Attrs(spec)
	c := e.start(a)
	res := c.expect(statusOK, "session to reissue")
	next, err := e.reissue(res.Handle(), a)
	if err != nil {
		t.Fatal(err)
	}
	got := next.expect(statusOK, "reissued session")
	if got.Attrs().Lineage() != a.Lineage() || got.Handle().Lineage() != a.Lineage() {
		t.Fatal("Reissue changed the session id")
	}
	if got.Handle().ID() == res.Handle().ID() {
		t.Fatal("Reissue kept the old family")
	}
	c.expect(statusUnauth, "family replaced by Reissue")
	if _, err := e.reissue(res.Handle(), a); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Reissue of a replaced family: %v", err)
	}
	other := principaltest.Attrs(e.passwordSpec(s, core.TransportCookies))
	if _, err := e.reissue(got.Handle(), other); !errors.Is(err, session.ErrHandleMismatch) {
		t.Fatalf("Reissue onto another lineage: %v", err)
	}
	e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
	renewed := next.expect(statusOK, "renewal after Reissue")
	if renewed.Attrs().Lineage() != a.Lineage() {
		t.Fatal("renewal changed the session id")
	}
	spec.PrimaryAt, spec.SecondAt, spec.ClaimsFetchedAt = e.now(), e.now(), e.now()
	reauth := principaltest.Attrs(spec)
	again, err := e.reissue(renewed.Handle(), reauth)
	if err != nil {
		t.Fatalf("Reissue after reauthentication: %v", err)
	}
	got = again.expect(statusOK, "reauthenticated session")
	e.sameAttrs(got.Attrs(), reauth, "reauthenticated session")
	if got.Handle().Lineage() != a.Lineage() {
		t.Fatal("reauthentication changed the session id")
	}
	next.expect(statusUnauth, "family replaced by reauthentication")
}

func keptLineageSurvives(t *testing.T, e *env) {
	s := e.newUser()
	kept := principaltest.Attrs(e.passwordSpec(s, core.TransportCookies))
	c := e.start(kept)
	other := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	res := c.expect(statusOK, "session to keep")
	next, err := e.reissue(res.Handle(), kept)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.b.OnCredentialRotated(t.Context(), lifecycle.CredentialRotated{Subject: s, Keep: kept.Lineage(), Reason: lifecycle.RotationPasswordChanged}); err != nil {
		t.Fatal(err)
	}
	next.expect(statusOK, "kept lineage minted in the second of the revocation")
	other.expect(statusUnauth, "other lineage")
	for range 3 {
		e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
		next.expect(statusOK, "kept lineage keeps renewing")
	}
}

func renewedFamilyOwned(t *testing.T, e *env) {
	s := e.newUser()
	c := e.start(principaltest.Attrs(e.passwordSpec(s, core.TransportCookies)))
	e.fx.Claims.Set([]byte(`{"sub":"` + uuid.NewString() + `","tid":"other","roles":["user"]}`))
	e.advance(e.fx.Lifetimes.RecheckEvery + time.Second)
	res := c.expect(statusOK, "renewal")
	if res.Attrs().Subject() != s || res.Handle().Subject() != s {
		t.Fatal("renewal took the subject from the claims source")
	}
	if err := e.b.OnDisabled(t.Context(), lifecycle.AccountEvent{Subject: s}); err != nil {
		t.Fatal(err)
	}
	c.expect(statusUnauth, "per-subject revocation of a renewed family")
}

func endRevokes(t *testing.T, e *env) {
	for _, tr := range []core.Transport{core.TransportCookies, core.TransportBearer} {
		s := e.newUser()
		c := e.start(principaltest.Attrs(e.passwordSpec(s, tr)))
		c.expect(statusOK, "live session")
		stolen := c.clone()
		if err := c.end(); err != nil {
			t.Fatal(err)
		}
		if tr == core.TransportCookies && len(c.cookies) != 0 {
			t.Fatal("End did not clear the session cookies")
		}
		stolen.expect(statusUnauth, "credentials of an ended session")
		if err := stolen.end(); err != nil {
			t.Fatalf("End is not idempotent: %v", err)
		}
		if err := e.client().end(); err != nil {
			t.Fatalf("End without credentials: %v", err)
		}
	}
}

func reportsDurability(t *testing.T, e *env) {
	if !e.b.Durability().Valid() {
		t.Fatal("invalid durability")
	}
}
