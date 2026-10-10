package session_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/session"
)

var family = uuid.MustParse("11111111-2222-4333-8444-555555555555")

func otherLineage(a core.SessionAttrs) core.SessionAttrs {
	return core.ForTestSessionAttrs(core.ForTestAttrs{
		Lineage:   uuid.MustParse("22222222-3333-4444-8555-666666666666"),
		Subject:   a.Subject(),
		Factors:   a.Factors(),
		PrimaryAt: a.PrimaryAt(),
		Epoch:     a.Epoch(),
		Transport: a.Transport(),
		CreatedAt: a.CreatedAt(),
	})
}

func TestNewHandleBindsTheSession(t *testing.T) {
	a := principaltest.Full()
	h, err := session.NewHandle(a, family)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID() != family || h.Subject() != a.Subject() || h.Lineage() != a.Lineage() || h.IsZero() {
		t.Fatal("handle does not carry the session's subject, lineage and id")
	}
	if _, err := session.NewHandle(core.SessionAttrs{}, family); !errors.Is(err, session.ErrHandleMismatch) {
		t.Fatal("zero attributes must be refused")
	}
	if _, err := session.NewHandle(a, uuid.Nil); !errors.Is(err, session.ErrHandleMismatch) {
		t.Fatal("a nil id must be refused")
	}
	if !(session.Handle{}).IsZero() {
		t.Fatal("the zero Handle is zero")
	}
}

func TestNewResumedRefusesAHandleOfAnotherSession(t *testing.T) {
	a := principaltest.Full()
	c := core.NewSealedClaims([]byte(`{"roles":["admin"]}`))
	h, err := session.NewHandle(a, family)
	if err != nil {
		t.Fatal(err)
	}
	r, err := session.NewResumed(a, c, h)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Attrs(), a) || string(r.Claims().Bytes()) != string(c.Bytes()) || r.Handle() != h {
		t.Fatal("resumed session does not return its parts")
	}
	other, err := session.NewHandle(otherLineage(a), family)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewResumed(a, c, other); !errors.Is(err, session.ErrHandleMismatch) {
		t.Fatal("a handle of another lineage must be refused")
	}
	if _, err := session.NewResumed(a, c, session.Handle{}); !errors.Is(err, session.ErrHandleMismatch) {
		t.Fatal("a zero handle must be refused")
	}
	if _, err := session.NewResumed(core.SessionAttrs{}, c, h); !errors.Is(err, session.ErrHandleMismatch) {
		t.Fatal("zero attributes must be refused")
	}
}

func TestBackendContract(t *testing.T) {
	bt := reflect.TypeOf((*session.Backend)(nil)).Elem()
	if !bt.Implements(reflect.TypeOf((*lifecycle.Subscriber)(nil)).Elem()) {
		t.Fatal("Backend must embed lifecycle.Subscriber so every backend decides every event")
	}
	want := map[string]string{
		"Start":      "func(context.Context, http.ResponseWriter, core.SessionAttrs, core.SealedClaims) error",
		"Resume":     "func(context.Context, http.ResponseWriter, *http.Request, core.TenantID) (session.Resumed, error)",
		"Reissue":    "func(context.Context, http.ResponseWriter, session.Handle, core.SessionAttrs) error",
		"End":        "func(context.Context, http.ResponseWriter, *http.Request) error",
		"Durability": "func() store.Durability",
	}
	for name, sig := range want {
		m, ok := bt.MethodByName(name)
		if !ok {
			t.Errorf("Backend lacks %s", name)
			continue
		}
		if got := m.Type.String(); got != sig {
			t.Errorf("Backend.%s is %s, want %s (DESIGN §3.10)", name, got, sig)
		}
	}
	if bt.NumMethod() != len(want)+reflect.TypeOf((*lifecycle.Subscriber)(nil)).Elem().NumMethod() {
		t.Fatalf("Backend has %d methods; it must be exactly §3.10 plus lifecycle.Subscriber", bt.NumMethod())
	}
}
