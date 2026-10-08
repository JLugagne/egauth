package tokens_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/tokens"
)

func TestRefreshSpecCannotCarryAnIndependentSealedValue(t *testing.T) {
	typ := reflect.TypeOf(tokens.RefreshSpec{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type == reflect.TypeOf(principal.Sealed{}) {
			t.Fatalf("RefreshSpec.%s lets a caller pair attributes with another session's sealed value", typ.Field(i).Name)
		}
	}
}

func TestNewRefreshRecordSealsTheAttributesItIndexes(t *testing.T) {
	s := spec(t)
	var got core.SessionAttrs
	seal := func(a principal.SessionAttrs) (principal.Sealed, error) {
		got = a
		return core.Seal(a)
	}
	r, err := tokens.NewRefreshRecord(s, seal)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, s.Attrs) {
		t.Fatal("the sealer must receive the attributes the index fields come from")
	}
	back, err := core.Unseal(r.Sealed())
	if err != nil || back.Subject() != r.Subject() || back.Lineage() != r.Lineage() || back.Epoch() != r.Epoch() {
		t.Fatalf("sealed value and index fields disagree: %v", err)
	}
}

func TestNewRefreshRecordRefusesAMissingOrFailingSealer(t *testing.T) {
	if _, err := tokens.NewRefreshRecord(spec(t), nil); !errors.Is(err, tokens.ErrInvalidRecord) {
		t.Fatalf("nil sealer: want ErrInvalidRecord, got %v", err)
	}
	boom := errors.New("boom")
	failing := func(principal.SessionAttrs) (principal.Sealed, error) { return principal.Sealed{}, boom }
	if _, err := tokens.NewRefreshRecord(spec(t), failing); !errors.Is(err, tokens.ErrInvalidRecord) || !errors.Is(err, boom) {
		t.Fatalf("failing sealer: want ErrInvalidRecord joined with the cause, got %v", err)
	}
	empty := func(principal.SessionAttrs) (principal.Sealed, error) { return principal.Sealed{}, nil }
	if _, err := tokens.NewRefreshRecord(spec(t), empty); !errors.Is(err, tokens.ErrInvalidRecord) {
		t.Fatalf("empty sealed value: want ErrInvalidRecord, got %v", err)
	}
}

func TestNewRefreshRecordRefusesAnIssuingTimeBeforeTheLineage(t *testing.T) {
	s := spec(t)
	s.Now = s.Attrs.CreatedAt().Add(-48 * time.Hour)
	if _, err := tokens.NewRefreshRecord(s, core.Seal); !errors.Is(err, tokens.ErrInvalidRecord) {
		t.Fatalf("a token issued before its own session was admitted betrays a wrong clock, got %v", err)
	}
	s.Now = s.Attrs.CreatedAt().Add(-time.Second)
	if _, err := tokens.NewRefreshRecord(s, core.Seal); err != nil {
		t.Fatalf("a second of skew between replicas must be tolerated: %v", err)
	}
}
