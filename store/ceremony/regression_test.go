package ceremony_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/ceremony"
)

func TestValidateRefusesAReplacedPending(t *testing.T) {
	r, err := ceremony.NewRecord(pendingSpec(t, ceremony.MFAFlow), openPending)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("a built record must validate: %v", err)
	}
	r.Pending = principal.SealedFromBytes([]byte("garbage-pending"))
	if err := r.Validate(); !errors.Is(err, ceremony.ErrInvalidRecord) {
		t.Fatalf("a record whose Pending was replaced after NewRecord must not validate, got %v", err)
	}
	back, err := ceremony.Restore(rowOf(r))
	if err != nil || back.Validate() != nil {
		t.Fatalf("Restore binds the Pending it was given: %v", err)
	}
}

func TestNewRecordTakesTenantAndExpiryFromThePending(t *testing.T) {
	full := principaltest.FullPending()
	other, err := principal.ParseTenantID("other-tenant")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ceremony.NewRecord(pendingSpec(t, ceremony.MagicLink), openPending)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tenant() != full.Tenant() || r.Tenant() == other {
		t.Fatalf("an identifier-scoped record must carry the sealed Pending's tenant, got %q", r.Tenant())
	}
	if r.ExpiresAt().After(full.ExpiresAt()) {
		t.Fatal("a session-admitting record must not outlive the sealed Pending")
	}
}

func TestNewRecordChecksTheScopeAgainstTheSealedPending(t *testing.T) {
	full := principaltest.FullPending()
	subject, _ := full.Subject()
	s := pendingSpec(t, ceremony.MFAFlow)
	s.Scope = ceremony.SubjectScope(principal.Subject{Tenant: subject.Tenant, User: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")})
	if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrScopeMismatch) {
		t.Fatalf("a subject scope other than the bound Pending's subject: want ErrScopeMismatch, got %v", err)
	}
	lying := func(principal.Sealed) (ceremony.PendingBinding, error) {
		other, err := principal.ParseTenantID("other-tenant")
		if err != nil {
			return ceremony.PendingBinding{}, err
		}
		return ceremony.PendingBinding{Tenant: other, Subject: subject, ExpiresAt: full.ExpiresAt()}, nil
	}
	if _, err := ceremony.NewRecord(pendingSpec(t, ceremony.MFAFlow), lying); !errors.Is(err, ceremony.ErrScopeMismatch) {
		t.Fatalf("a Pending subject of another tenant than the Pending: want ErrScopeMismatch, got %v", err)
	}
}

func TestNewRecordRefusesAnUnopenablePending(t *testing.T) {
	s := pendingSpec(t, ceremony.PasswordReset)
	if _, err := ceremony.NewRecord(s, nil); !errors.Is(err, ceremony.ErrInvalidRecord) {
		t.Fatalf("nil opener: want ErrInvalidRecord, got %v", err)
	}
	s.Pending = principal.SealedFromBytes([]byte("not-a-pending"))
	if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrInvalidRecord) {
		t.Fatalf("undecodable Pending: want ErrInvalidRecord, got %v", err)
	}
	noEnd := func(p principal.Sealed) (ceremony.PendingBinding, error) {
		b, err := openPending(p)
		b.ExpiresAt = time.Time{}
		return b, err
	}
	if _, err := ceremony.NewRecord(pendingSpec(t, ceremony.PasswordReset), noEnd); !errors.Is(err, ceremony.ErrInvalidRecord) {
		t.Fatalf("no pending expiry: want ErrInvalidRecord, got %v", err)
	}
}

func TestNonAdmittingKindsOutliveTheirPending(t *testing.T) {
	full := principaltest.FullPending()
	for _, k := range []ceremony.Kind{ceremony.PasswordReset, ceremony.EmailVerification, ceremony.SecurityRevert} {
		r, err := ceremony.NewRecord(pendingSpec(t, k), openPending)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if !r.ExpiresAt().After(full.ExpiresAt()) {
			t.Fatalf("%s: a non-admitting record keeps its own TTL past the Pending", k)
		}
	}
}

func TestMarkConsumedHasItsOwnStoredKindError(t *testing.T) {
	if errors.Is(ceremony.ErrStoredKind, ceremony.ErrStatelessKind) || ceremony.ErrStoredKind.Error() == ceremony.ErrStatelessKind.Error() {
		t.Fatal("MarkConsumed on a stored kind must not reuse ErrStatelessKind")
	}
}

func TestNewRecordRefusesAnExpiredPendingForEveryKind(t *testing.T) {
	full := principaltest.FullPending()
	for _, k := range ceremony.All() {
		if k.Stateless() {
			continue
		}
		s := pendingSpec(t, k)
		s.Now = full.ExpiresAt().Add(time.Hour)
		if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrExpired) {
			t.Errorf("%s: a Pending already expired at writing time must be refused with ErrExpired, got %v", k, err)
		}
		s.Now = full.ExpiresAt()
		if _, err := ceremony.NewRecord(s, openPending); !errors.Is(err, ceremony.ErrExpired) {
			t.Errorf("%s: a Pending expiring at writing time must be refused with ErrExpired, got %v", k, err)
		}
	}
}

func TestScopedToChecksTheSubjectOfAHandleLookup(t *testing.T) {
	full := principaltest.FullPending()
	subject, _ := full.Subject()
	r, err := ceremony.NewRecord(pendingSpec(t, ceremony.PhoneVerification), openPending)
	if err != nil {
		t.Fatal(err)
	}
	if !r.ScopedTo(ceremony.SubjectScope(subject)) {
		t.Fatal("a phone verification record belongs to the subject it was written for")
	}
	other := principal.Subject{Tenant: subject.Tenant, User: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")}
	if r.ScopedTo(ceremony.SubjectScope(other)) || r.ScopedTo(ceremony.Scope{}) {
		t.Fatal("a record found by handle must not be accepted for another subject")
	}
	mac, err := ceremony.IdentifierScope(subject.User[:])
	if err == nil && r.ScopedTo(mac) {
		t.Fatal("a subject-scoped record must not match an identifier scope")
	}
	otherTenant, err := principal.ParseTenantID("other-tenant")
	if err != nil {
		t.Fatal(err)
	}
	if r.ScopedTo(ceremony.SubjectScope(principal.Subject{Tenant: otherTenant, User: subject.User})) {
		t.Fatal("a record must not match the same user id in another tenant")
	}
}
