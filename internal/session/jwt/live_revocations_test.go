package jwt_test

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/store/tokens"
)

func TestLiveRefusesAFamilyThisInstanceRevokedOnRefreshReuse(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	access, first := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
	rec := httptest.NewRecorder()
	if _, err := w.backend.Resume(ctx, rec, bearerRequest(t, access, first), tenant(t)); err != nil {
		t.Fatal(err)
	}
	access2, refresh2 := rec.Header().Get(jwt.HeaderAccessToken), rec.Header().Get(jwt.HeaderRefreshToken)
	if err := w.families.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := w.backend.Resume(ctx, httptest.NewRecorder(), bearerRequest(t, access2, refresh2), tenant(t))
	if err != nil {
		t.Fatal(err)
	}
	c, err := res.Caller()
	if err != nil {
		t.Fatal(err)
	}
	h, err := session.HandleOf(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.backend.Live(ctx, h); err != nil {
		t.Fatalf("live before the replay: %v", err)
	}
	replay := bearerRequest(t, "", first)
	replay.Header.Set("User-Agent", "attacker")
	if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), replay, tenant(t)); !errors.Is(err, tokens.ErrReused) {
		t.Fatalf("replay of the consumed refresh token: %v, want ErrReused", err)
	}
	if st, err := w.tokens.FamilyState(ctx, tenant(t), h.ID()); err != nil || !st.Revoked {
		t.Fatalf("the store did not revoke the family on reuse: %+v, %v", st, err)
	}
	if err := w.backend.Live(ctx, h); !errors.Is(err, session.ErrEnded) {
		t.Fatalf("Live right after this instance revoked the family on refresh reuse = %v, want session.ErrEnded", err)
	}
}

func TestLiveRefusesASessionOfATenantThisInstanceErased(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	if err := w.families.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	s := mustUser(t, w)
	access, refresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	res, err := w.backend.Resume(ctx, httptest.NewRecorder(), bearerRequest(t, access, refresh), tenant(t))
	if err != nil {
		t.Fatal(err)
	}
	c, err := res.Caller()
	if err != nil {
		t.Fatal(err)
	}
	h, err := session.HandleOf(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.backend.Live(ctx, h); err != nil {
		t.Fatalf("live before the erase: %v", err)
	}
	if err := w.backend.OnTenantErased(ctx, lifecycle.TenantErased{Tenant: tenant(t)}); err != nil {
		t.Fatal(err)
	}
	if err := w.backend.Live(ctx, h); !errors.Is(err, session.ErrEnded) {
		t.Fatalf("Live right after this instance erased the tenant = %v, want session.ErrEnded", err)
	}
}
