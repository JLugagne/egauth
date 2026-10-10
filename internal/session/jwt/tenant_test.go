package jwt_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/principal"
)

func TestResumeUnderAnotherTenantConsumesNothing(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	other, err := principal.ParseTenantID("globex")
	if err != nil {
		t.Fatal(err)
	}
	s := mustUser(t, w)
	for _, tr := range []core.Transport{core.TransportBearer, core.TransportCookies} {
		access, refresh := startPair(t, w, passwordAttrs(t, w, s, tr))
		present := func(access string) *http.Request {
			if tr == core.TransportCookies {
				return cookieRequest(t, w, access, refresh)
			}
			return bearerRequest(t, access, refresh)
		}
		if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), present(access), other); !errors.Is(err, session.ErrTenantMismatch) {
			t.Fatalf("live access token under another tenant: %v, want ErrTenantMismatch", err)
		}
		fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
		for _, a := range []string{access, ""} {
			rec := httptest.NewRecorder()
			if _, err := w.backend.Resume(ctx, rec, present(a), other); !errors.Is(err, session.ErrTenantMismatch) {
				t.Fatalf("expired session under another tenant: %v, want ErrTenantMismatch", err)
			}
			if len(rec.Header()) != 0 {
				t.Fatalf("a cross-tenant Resume wrote %v", rec.Header())
			}
		}
		fx.Clock.Advance(time.Minute)
		if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), present(access), tenant(t)); err != nil {
			t.Fatalf("the refresh token was consumed by a cross-tenant Resume: %v", err)
		}
	}
}
