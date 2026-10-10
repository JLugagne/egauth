package stateful_test

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

func TestResumeUnderAnotherTenantTouchesNothing(t *testing.T) {
	w := buildWorld(t, backendtest.NewFixture(t))
	other, err := principal.ParseTenantID("globex")
	if err != nil {
		t.Fatal(err)
	}
	s := mustUser(t, w)
	for _, tr := range []core.Transport{core.TransportBearer, core.TransportCookies} {
		tok, _ := start(t, w, attrsFor(t, w, s, tr, false))
		present := func() *http.Request {
			if tr == core.TransportCookies {
				return cookieRequest(t, w, tok)
			}
			return bearerRequest(t, tok)
		}
		for _, advance := range []time.Duration{0, w.fx.Lifetimes.RecheckEvery + time.Second} {
			w.fx.Clock.Advance(advance)
			rec := httptest.NewRecorder()
			if _, err := w.backend.Resume(t.Context(), rec, present(), other); !errors.Is(err, session.ErrTenantMismatch) {
				t.Fatalf("session under another tenant: %v, want ErrTenantMismatch", err)
			}
			if len(rec.Header()) != 0 {
				t.Fatalf("a cross-tenant Resume wrote %v", rec.Header())
			}
		}
		if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), present(), tenant(t)); err != nil {
			t.Fatalf("own tenant after a cross-tenant Resume: %v", err)
		}
	}
}
