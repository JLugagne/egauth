package sessions_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/sessions"
)

func TestSpecCannotCarryAnIndependentSealedValue(t *testing.T) {
	typ := reflect.TypeFor[sessions.Spec]()
	for field := range typ.Fields() {
		if field.Type == reflect.TypeFor[principal.Sealed]() {
			t.Fatalf("Spec.%s lets a caller pair attributes with another session's sealed value", field.Name)
		}
	}
}

func TestNewRecordSealsTheAttributesItIndexes(t *testing.T) {
	r, err := sessions.NewRecord(spec(t), core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	back, err := core.Unseal(r.Sealed())
	if err != nil || back.Subject() != r.Subject() || back.Lineage() != r.Lineage() || back.Epoch() != r.Epoch() {
		t.Fatalf("sealed value and index fields disagree: %v", err)
	}
	if _, err := sessions.NewRecord(spec(t), nil); !errors.Is(err, sessions.ErrInvalidRecord) {
		t.Fatalf("nil sealer: want ErrInvalidRecord, got %v", err)
	}
	boom := errors.New("boom")
	failing := func(principal.SessionAttrs) (principal.Sealed, error) { return principal.Sealed{}, boom }
	if _, err := sessions.NewRecord(spec(t), failing); !errors.Is(err, sessions.ErrInvalidRecord) || !errors.Is(err, boom) {
		t.Fatalf("failing sealer: want ErrInvalidRecord joined with the cause, got %v", err)
	}
}

type handleKeyedStore interface {
	Replace(ctx context.Context, req sessions.ReplaceRequest) error
	RevokeSession(ctx context.Context, s principal.Subject, id uuid.UUID) error
}

func TestStatefulReissueAndSessionEndNeedOnlyTheHandle(t *testing.T) {
	st := reflect.TypeFor[sessions.Store]()
	if !st.Implements(reflect.TypeFor[handleKeyedStore]()) {
		t.Fatal("sessions.Store must replace and revoke a row by the id a session.Handle carries")
	}
	s := spec(t)
	r, err := sessions.NewRecord(s, core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	h, err := session.NewHandle(s.Attrs, r.ID())
	if err != nil {
		t.Fatal(err)
	}
	req := sessions.ReplaceRequest{Previous: h.ID(), Next: r}
	if req.Previous != r.ID() || h.Subject() != r.Subject() || h.Lineage() != r.Lineage() {
		t.Fatal("a Handle built from a row must address that row")
	}
}

func TestNewRecordRefusesAWritingTimeBeforeTheLineage(t *testing.T) {
	s := spec(t)
	s.Now = s.Attrs.CreatedAt().Add(-48 * time.Hour)
	if _, err := sessions.NewRecord(s, core.Seal); !errors.Is(err, sessions.ErrInvalidRecord) {
		t.Fatalf("a row written before its own session was admitted betrays a wrong clock, got %v", err)
	}
	s.Now = s.Attrs.CreatedAt().Add(-time.Second)
	if _, err := sessions.NewRecord(s, core.Seal); err != nil {
		t.Fatalf("a second of skew between replicas must be tolerated: %v", err)
	}
}
