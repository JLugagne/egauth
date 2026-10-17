package jwt_test

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/store/tokens"
)

func TestConsumedRefreshTokenReplayedPastItsIdleWindowRevokesTheFamily(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	access, first := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	renew := func(access, refresh string) (string, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		if _, err := w.backend.Resume(ctx, rec, bearerRequest(t, access, refresh), tenant(t)); err != nil {
			t.Fatal(err)
		}
		return rec.Header().Get(jwt.HeaderAccessToken), rec.Header().Get(jwt.HeaderRefreshToken)
	}
	fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
	access, refresh := renew(access, first)
	fx.Clock.Advance(50 * time.Minute)
	access, refresh = renew(access, refresh)
	fx.Clock.Advance(20 * time.Minute)
	_, err := w.backend.Resume(ctx, httptest.NewRecorder(), bearerRequest(t, "", first), tenant(t))
	if !errors.Is(err, tokens.ErrReused) {
		t.Fatalf("consumed refresh token replayed past its idle window: %v, want reuse", err)
	}
	if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), bearerRequest(t, access, refresh), tenant(t)); !errors.Is(err, tokens.ErrRevoked) {
		t.Fatalf("legitimate session after the replay: %v, want its family revoked", err)
	}
}
