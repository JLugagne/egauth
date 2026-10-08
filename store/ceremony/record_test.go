package ceremony_test

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
	"github.com/JLugagne/egauth/store/ceremony"
)

var (
	handle32 = bytes.Repeat([]byte{0x5a}, ceremony.HandleHashLen)
	mac32    = bytes.Repeat([]byte{0x17}, ceremony.IdentifierScopeLen)
)

func pendingSpec(t *testing.T, k ceremony.Kind) ceremony.Spec {
	t.Helper()
	p := principaltest.FullPending()
	sp, err := core.SealPending(p)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := p.Subject()
	scope := ceremony.SubjectScope(subject)
	if k.Scope() == ceremony.Identifier {
		if scope, err = ceremony.IdentifierScope(mac32); err != nil {
			t.Fatal(err)
		}
	}
	return ceremony.Spec{
		Kind:       k,
		HandleHash: slices.Clone(handle32),
		Scope:      scope,
		Pending:    sp,
		Payload:    []byte("typed-payload"),
		Now:        p.ExpiresAt().Add(-10 * time.Minute),
	}
}

func openPending(s principal.Sealed) (ceremony.PendingBinding, error) {
	p, err := core.UnsealPending(s)
	if err != nil {
		return ceremony.PendingBinding{}, err
	}
	sub, _ := p.Subject()
	return ceremony.PendingBinding{Tenant: p.Tenant(), Subject: sub, ExpiresAt: p.ExpiresAt()}, nil
}

func TestNewRecordForEveryStoredKind(t *testing.T) {
	for _, k := range ceremony.All() {
		if k.Stateless() {
			continue
		}
		s := pendingSpec(t, k)
		full := principaltest.FullPending()
		r, err := ceremony.NewRecord(s, openPending)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if r.Kind() != k || r.Tenant() != full.Tenant() || r.Attempts() != 0 || !r.CreatedAt().Equal(s.Now) {
			t.Fatalf("%s: record fields not taken from the spec", k)
		}
		if !r.ExpiresAt().Equal(k.ExpiresAt(full.ExpiresAt(), s.Now)) {
			t.Fatalf("%s: expiry %s does not come from Kind.ExpiresAt", k, r.ExpiresAt())
		}
		if k.AdmitsSession() && r.ExpiresAt().After(full.ExpiresAt()) {
			t.Fatalf("%s: record outlives its Pending", k)
		}
		if !bytes.Equal(r.ScopeHash(), s.Scope.Hash()) || !bytes.Equal(r.Pending.Bytes(), s.Pending.Bytes()) {
			t.Fatalf("%s: scope or pending not kept verbatim", k)
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: a built record must validate: %v", k, err)
		}
	}
}

func TestSubjectScopeHashIsTheUserID(t *testing.T) {
	p := principaltest.FullPending()
	subject, _ := p.Subject()
	sc := ceremony.SubjectScope(subject)
	if sc.Class() != ceremony.Subject || !bytes.Equal(sc.Hash(), subject.User[:]) {
		t.Fatal("subject scope must hash to the user id")
	}
	if (ceremony.SubjectScope(principal.Subject{})).Class() != 0 {
		t.Fatal("a zero subject yields the invalid zero Scope")
	}
	if _, err := ceremony.IdentifierScope([]byte("short")); !errors.Is(err, ceremony.ErrScopeMismatch) {
		t.Fatal("an identifier scope must be a full HMAC-SHA256")
	}
}

func TestNewRecordRefusesStatelessKinds(t *testing.T) {
	for _, k := range ceremony.All() {
		if !k.Stateless() {
			continue
		}
		s := pendingSpec(t, ceremony.MagicLink)
		s.Kind = k
		if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrStatelessKind) {
			t.Fatalf("%s: want ErrStatelessKind, got %v", k, err)
		}
	}
}

func TestShortCodeIsNeverAKey(t *testing.T) {
	for _, k := range []ceremony.Kind{ceremony.EmailCode, ceremony.SMSCode, ceremony.PhoneVerification, ceremony.PasswordResetCode} {
		s := pendingSpec(t, k)
		s.HandleHash = []byte("123456")
		if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrHandleTooShort) {
			t.Fatalf("%s: a six-digit code used as key must be refused, got %v", k, err)
		}
		s.HandleHash = handle32[:ceremony.HandleHashLen-1]
		if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrHandleTooShort) {
			t.Fatalf("%s: a 31-byte handle hash must be refused, got %v", k, err)
		}
	}
}

func TestNewRecordChecksScopeAgainstKind(t *testing.T) {
	s := pendingSpec(t, ceremony.MFAFlow)
	idScope, err := ceremony.IdentifierScope(mac32)
	if err != nil {
		t.Fatal(err)
	}
	s.Scope = idScope
	if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrScopeMismatch) {
		t.Fatalf("subject kind with identifier scope: want ErrScopeMismatch, got %v", err)
	}
	s = pendingSpec(t, ceremony.MagicLink)
	p := principaltest.FullPending()
	subject, _ := p.Subject()
	s.Scope = ceremony.SubjectScope(subject)
	if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrScopeMismatch) {
		t.Fatalf("identifier kind with subject scope: want ErrScopeMismatch, got %v", err)
	}
	s = pendingSpec(t, ceremony.PasswordReset)
	other, err := principal.ParseTenantID("tenant-other")
	if err != nil {
		t.Fatal(err)
	}
	s.Scope = ceremony.SubjectScope(principal.Subject{Tenant: other, User: subject.User})
	if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrScopeMismatch) {
		t.Fatalf("subject scope of another tenant: want ErrScopeMismatch, got %v", err)
	}
	s = pendingSpec(t, ceremony.PasswordReset)
	s.Scope = ceremony.Scope{}
	if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrScopeMismatch) {
		t.Fatalf("zero scope: want ErrScopeMismatch, got %v", err)
	}
}

func TestNewRecordRefusesAnExpiredPending(t *testing.T) {
	s := pendingSpec(t, ceremony.MFAFlow)
	s.Now = principaltest.FullPending().ExpiresAt()
	if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestNewRecordRefusesIncompleteSpecs(t *testing.T) {
	cases := map[string]func(*ceremony.Spec){
		"invalid kind":    func(s *ceremony.Spec) { s.Kind = 0 },
		"zero pending":    func(s *ceremony.Spec) { s.Pending = principal.Sealed{} },
		"no now":          func(s *ceremony.Spec) { s.Now = time.Time{} },
		"huge payload":    func(s *ceremony.Spec) { s.Payload = make([]byte, ceremony.MaxPayloadLen+1) },
		"long handle":     func(s *ceremony.Spec) { s.HandleHash = make([]byte, ceremony.MaxHandleHashLen+1) },
		"kind past range": func(s *ceremony.Spec) { s.Kind = 200 },
	}
	for name, mutate := range cases {
		s := pendingSpec(t, ceremony.PasswordReset)
		mutate(&s)
		if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrInvalidRecord) {
			t.Errorf("%s: want ErrInvalidRecord, got %v", name, err)
		}
	}
}

func rowOf(r ceremony.Record) ceremony.Row {
	return ceremony.Row{
		Tenant:     r.Tenant(),
		Kind:       r.Kind(),
		HandleHash: r.HandleHash(),
		ScopeHash:  r.ScopeHash(),
		Pending:    r.Pending,
		Payload:    r.Payload(),
		Attempts:   r.Attempts(),
		ExpiresAt:  r.ExpiresAt(),
		CreatedAt:  r.CreatedAt(),
	}
}

func TestRestoreRoundTripsAndRefusesInconsistentRows(t *testing.T) {
	r, err := ceremony.NewRecord(pendingSpec(t, ceremony.EmailCode), openPending)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ceremony.Restore(rowOf(r))
	if err != nil || !reflect.DeepEqual(back, r) {
		t.Fatalf("restored record differs from the original: %v", err)
	}
	charged := rowOf(r)
	charged.Attempts = ceremony.EmailCode.MaxAttempts() - 1
	if _, err := ceremony.Restore(charged); err != nil {
		t.Fatalf("a record one attempt from its bound is still live: %v", err)
	}
	cases := map[string]func(*ceremony.Row){
		"attempts at bound": func(w *ceremony.Row) { w.Attempts = ceremony.EmailCode.MaxAttempts() },
		"negative attempts": func(w *ceremony.Row) { w.Attempts = -1 },
		"outlives its kind": func(w *ceremony.Row) { w.ExpiresAt = w.CreatedAt.Add(ceremony.EmailCode.TTL() + time.Second) },
		"expires at birth":  func(w *ceremony.Row) { w.ExpiresAt = w.CreatedAt },
	}
	for name, mutate := range cases {
		w := rowOf(r)
		mutate(&w)
		if _, err := ceremony.Restore(w); !errors.Is(err, ceremony.ErrInvalidRecord) {
			t.Errorf("%s: want ErrInvalidRecord, got %v", name, err)
		}
	}
	w := rowOf(r)
	w.ScopeHash = uuid.Nil[:]
	sub, err := ceremony.NewRecord(pendingSpec(t, ceremony.PasswordReset), openPending)
	if err != nil {
		t.Fatal(err)
	}
	ws := rowOf(sub)
	ws.ScopeHash = uuid.Nil[:]
	if _, err := ceremony.Restore(ws); !errors.Is(err, ceremony.ErrScopeMismatch) {
		t.Errorf("nil subject scope: want ErrScopeMismatch, got %v", err)
	}
	if _, err := ceremony.Restore(w); !errors.Is(err, ceremony.ErrScopeMismatch) {
		t.Errorf("16-byte scope on an identifier kind: want ErrScopeMismatch, got %v", err)
	}
}

func TestRecordLiteralIsRefused(t *testing.T) {
	r, err := ceremony.NewRecord(pendingSpec(t, ceremony.MFAFlow), openPending)
	if err != nil {
		t.Fatal(err)
	}
	if err := (ceremony.Record{Pending: r.Pending}).Validate(); err == nil {
		t.Fatal("a Record literal cannot carry index fields and must not validate")
	}
}

func TestStoreContract(t *testing.T) {
	st := reflect.TypeOf((*ceremony.Store)(nil)).Elem()
	for _, base := range []reflect.Type{
		reflect.TypeOf((*store.Base)(nil)).Elem(),
		reflect.TypeOf((*store.Reaper)(nil)).Elem(),
	} {
		if !st.Implements(base) {
			t.Fatalf("ceremony.Store must embed %s", base)
		}
	}
	want := map[string]string{
		"Put":            "func(context.Context, ceremony.Record) (int, error)",
		"Peek":           "func(context.Context, core.TenantID, ceremony.Kind, []uint8) (ceremony.Record, error)",
		"Consume":        "func(context.Context, core.TenantID, ceremony.Kind, []uint8) (ceremony.Record, error)",
		"RecordFailure":  "func(context.Context, core.TenantID, ceremony.Kind, []uint8) (int, error)",
		"MarkConsumed":   "func(context.Context, core.TenantID, ceremony.Kind, []uint8, time.Time) (bool, error)",
		"DeleteForScope": "func(context.Context, core.TenantID, []uint8, ...ceremony.Kind) (int64, error)",
	}
	for name, sig := range want {
		m, ok := st.MethodByName(name)
		if !ok {
			t.Errorf("ceremony.Store lacks %s", name)
			continue
		}
		if got := m.Type.String(); got != sig {
			t.Errorf("ceremony.Store.%s is %s, want %s (DESIGN §4.6)", name, got, sig)
		}
	}
}
