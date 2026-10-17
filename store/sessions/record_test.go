package sessions_test

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/sessions"
)

var (
	rowID  = uuid.MustParse("99999999-8888-4777-8666-555555555555")
	hash32 = bytes.Repeat([]byte{0xcd}, sessions.HashLen)
)

func spec(t *testing.T) sessions.Spec {
	t.Helper()
	a := principaltest.Full()
	return sessions.Spec{
		ID:                rowID,
		TokenHash:         slices.Clone(hash32),
		Attrs:             a,
		AppClaims:         []byte(`{"roles":["admin"]}`),
		ClientFingerprint: []byte("fp-client-a"),
		IdleTTL:           2 * time.Hour,
		MaxLifetime:       30 * 24 * time.Hour,
		Now:               a.CreatedAt().Add(time.Hour),
	}
}

func TestNewRecordDerivesIndexFieldsFromAttrs(t *testing.T) {
	s := spec(t)
	r, err := sessions.NewRecord(s, core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	a := s.Attrs
	if r.ID() != rowID || r.Subject() != a.Subject() || r.Tenant() != a.Subject().Tenant || r.Lineage() != a.Lineage() || r.Epoch() != a.Epoch() {
		t.Fatal("index fields not derived from the attributes")
	}
	if !r.AbsoluteExpiresAt().Equal(a.CreatedAt().Add(s.MaxLifetime)) {
		t.Fatalf("absolute expiry must count from the lineage admission, got %s", r.AbsoluteExpiresAt())
	}
	if !r.IdleExpiresAt().Equal(s.Now.Add(s.IdleTTL)) || !r.CheckedAt().Equal(s.Now) || !r.CreatedAt().Equal(s.Now) {
		t.Fatal("idle expiry, check and creation times must come from Now")
	}
	got, err := core.Unseal(r.Sealed())
	if err != nil || !reflect.DeepEqual(got, a) {
		t.Fatalf("sealed attributes do not round-trip: %v", err)
	}
	s.TokenHash[0] ^= 0xff
	if !bytes.Equal(r.TokenHash(), hash32) {
		t.Fatal("record aliases caller memory")
	}
}

func TestIdleExpiryNeverOutlivesTheLineage(t *testing.T) {
	s := spec(t)
	s.MaxLifetime = 90 * time.Minute
	r, err := sessions.NewRecord(s, core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	if !r.IdleExpiresAt().Equal(r.AbsoluteExpiresAt()) {
		t.Fatal("idle expiry must be clamped to the absolute expiry")
	}
	s.MaxLifetime = time.Hour
	if _, err := sessions.NewRecord(s, core.Seal); !errors.Is(err, sessions.ErrLifetimeExceeded) {
		t.Fatalf("want ErrLifetimeExceeded, got %v", err)
	}
}

func TestNewRecordRefusesIncompleteSpecs(t *testing.T) {
	cases := map[string]func(*sessions.Spec){
		"nil id":           func(s *sessions.Spec) { s.ID = uuid.Nil },
		"zero attrs":       func(s *sessions.Spec) { s.Attrs = core.SessionAttrs{} },
		"short hash":       func(s *sessions.Spec) { s.TokenHash = []byte("abc") },
		"no idle ttl":      func(s *sessions.Spec) { s.IdleTTL = 0 },
		"no max lifetime":  func(s *sessions.Spec) { s.MaxLifetime = 0 },
		"no now":           func(s *sessions.Spec) { s.Now = time.Time{} },
		"long fingerprint": func(s *sessions.Spec) { s.ClientFingerprint = make([]byte, sessions.MaxFingerprintLen+1) },
		"huge claims":      func(s *sessions.Spec) { s.AppClaims = make([]byte, sessions.MaxAppClaimsLen+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := spec(t)
			mutate(&s)
			if _, err := sessions.NewRecord(s, core.Seal); !errors.Is(err, sessions.ErrInvalidRecord) {
				t.Fatalf("want ErrInvalidRecord, got %v", err)
			}
		})
	}
}

func rowOf(r sessions.Record) sessions.Row {
	return sessions.Row{
		ID:                r.ID(),
		TokenHash:         r.TokenHash(),
		Subject:           r.Subject(),
		Lineage:           r.Lineage(),
		Sealed:            r.Sealed(),
		AppClaims:         r.AppClaims(),
		SecurityEpoch:     r.Epoch(),
		ClientFingerprint: r.ClientFingerprint(),
		IdleExpiresAt:     r.IdleExpiresAt(),
		AbsoluteExpiresAt: r.AbsoluteExpiresAt(),
		CheckedAt:         r.CheckedAt(),
		CreatedAt:         r.CreatedAt(),
	}
}

func TestRestoreRoundTripsAndRefusesInconsistentRows(t *testing.T) {
	r, err := sessions.NewRecord(spec(t), core.Seal)
	if err != nil {
		t.Fatal(err)
	}
	back, err := sessions.Restore(rowOf(r))
	if err != nil || !reflect.DeepEqual(back, r) {
		t.Fatalf("restored record differs from the original: %v", err)
	}
	cases := map[string]func(*sessions.Row){
		"idle past absolute":     func(w *sessions.Row) { w.IdleExpiresAt = w.AbsoluteExpiresAt.Add(time.Second) },
		"idle before check":      func(w *sessions.Row) { w.IdleExpiresAt = w.CheckedAt },
		"zero subject":           func(w *sessions.Row) { w.Subject = principal.Subject{} },
		"nil lineage":            func(w *sessions.Row) { w.Lineage = uuid.Nil },
		"created after absolute": func(w *sessions.Row) { w.CreatedAt = w.AbsoluteExpiresAt.Add(48 * time.Hour) },
		"checked before created": func(w *sessions.Row) {
			w.CheckedAt = w.CreatedAt.Add(-72 * time.Hour)
			w.IdleExpiresAt = w.CheckedAt.Add(time.Hour)
		},
	}
	for name, mutate := range cases {
		w := rowOf(r)
		mutate(&w)
		if _, err := sessions.Restore(w); !errors.Is(err, sessions.ErrInvalidRecord) {
			t.Errorf("%s: want ErrInvalidRecord, got %v", name, err)
		}
	}
	if !(sessions.Record{}).IsZero() || r.IsZero() {
		t.Fatal("IsZero must tell a built record from a literal")
	}
}

func TestStoreContract(t *testing.T) {
	st := reflect.TypeOf((*sessions.Store)(nil)).Elem()
	for _, base := range []reflect.Type{
		reflect.TypeOf((*store.Base)(nil)).Elem(),
		reflect.TypeOf((*store.Reaper)(nil)).Elem(),
	} {
		if !st.Implements(base) {
			t.Fatalf("sessions.Store must embed %s", base)
		}
	}
	for _, m := range []string{
		"Create", "Get", "Touch", "Rotate", "Replace", "Revoke", "RevokeSession", "RevokeForSubject", "RevocationsSince", "DeleteForSubject",
	} {
		if _, ok := st.MethodByName(m); !ok {
			t.Errorf("sessions.Store lacks %s", m)
		}
	}
	rot := reflect.TypeOf(sessions.RotateRequest{})
	if rot.NumField() != 2 || rot.Field(0).Type != reflect.TypeOf([]byte(nil)) || rot.Field(1).Type != reflect.TypeOf(sessions.Record{}) {
		t.Errorf("RotateRequest must wrap one hash and one sealed record")
	}
}
