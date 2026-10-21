package jwt_test

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
)

func TestLiveRefusesASessionThisInstanceJustEnded(t *testing.T) {
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
		t.Fatalf("live before End: %v", err)
	}
	if err := w.backend.End(ctx, httptest.NewRecorder(), bearerRequest(t, access, refresh), tenant(t)); err != nil {
		t.Fatal(err)
	}
	if err := w.backend.Live(ctx, h); !errors.Is(err, session.ErrEnded) {
		t.Fatalf("Live right after this instance ended the session = %v, want session.ErrEnded", err)
	}
}
