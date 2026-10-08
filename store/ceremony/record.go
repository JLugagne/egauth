package ceremony

import (
	"bytes"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
)

// HandleHashLen is the minimum length of a handle digest: the SHA-256 digest of a 256-bit random
// handle. A short code is compared against the payload, never used as a key (C-30).
const HandleHashLen = 32

// MaxHandleHashLen bounds a handle digest, in bytes.
const MaxHandleHashLen = 64

// IdentifierScopeLen is the length of an Identifier scope: HMAC-SHA256(data key, normalised
// identifier).
const IdentifierScopeLen = 32

// MaxPayloadLen bounds the encoded typed payload of a record, in bytes.
const MaxPayloadLen = 16 << 10

// Scope is what a record is grouped and capped by: a subject, or the keyed hash of an identifier.
// The zero Scope is invalid.
type Scope struct {
	class  ScopeClass
	tenant principal.TenantID
	hash   []byte
}

// SubjectScope scopes a record to s; its hash is the subject's user id.
func SubjectScope(s principal.Subject) Scope {
	if s.IsZero() {
		return Scope{}
	}
	return Scope{class: Subject, tenant: s.Tenant, hash: s.User[:]}
}

// IdentifierScope scopes a record to an identifier through mac, its HMAC-SHA256 under the data
// key. It returns ErrScopeMismatch unless mac is IdentifierScopeLen bytes.
func IdentifierScope(mac []byte) (Scope, error) {
	if len(mac) != IdentifierScopeLen {
		return Scope{}, ErrScopeMismatch
	}
	return Scope{class: Identifier, hash: slices.Clone(mac)}, nil
}

// Class returns the scope class, or zero for the zero Scope.
func (s Scope) Class() ScopeClass { return s.class }

// Hash returns the scope hash that Put caps by and DeleteForScope matches.
func (s Scope) Hash() []byte { return slices.Clone(s.hash) }

// PendingBinding is what a sealed Pending binds a record to: its tenant, its subject (zero while
// unbound) and its expiry.
type PendingBinding struct {
	Tenant    principal.TenantID
	Subject   principal.Subject
	ExpiresAt time.Time
}

// PendingOpener reads the binding of a sealed Pending; callers pass the core codec
// (core.UnsealPending and the Pending accessors). NewRecord derives the record's tenant and expiry
// from it, so they cannot disagree with the sealed value.
type PendingOpener func(principal.Sealed) (PendingBinding, error)

// Spec describes a ceremony record to write. Pending is the sealed core Pending of the journey; the
// record's tenant and expiry come from it. Now is the writing instant from the library clock.
type Spec struct {
	Kind       Kind
	HandleHash []byte
	Scope      Scope
	Pending    principal.Sealed
	Payload    []byte
	Now        time.Time
}

// Record is one stored ceremony. Its scope class, expiry and attempt bound come from its Kind,
// never from a call site; build it with NewRecord, or Restore in a store implementation.
type Record struct {
	// Pending is the sealed Pending, kept verbatim. Replacing it after NewRecord or Restore makes
	// Validate, and so Put, refuse the record.
	Pending    principal.Sealed
	pending    []byte
	tenant     principal.TenantID
	kind       Kind
	handleHash []byte
	scopeHash  []byte
	payload    []byte
	attempts   int
	expiresAt  time.Time
	createdAt  time.Time
}

// Row is the persisted shape of a Record, for store implementations.
type Row struct {
	Tenant     principal.TenantID
	Kind       Kind
	HandleHash []byte
	ScopeHash  []byte
	Pending    principal.Sealed
	Payload    []byte
	Attempts   int
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// NewRecord opens s.Pending with open and takes the record's tenant from it. It derives the expiry
// with Kind.ExpiresAt from the Pending's expiry, so a session-admitting record never outlives its
// Pending, and checks the scope against Kind.Scope and the Pending: a subject scope must be the
// Pending's tenant and, once the Pending is bound, its subject. It returns ErrStatelessKind for an
// anonymous kind, ErrHandleTooShort, ErrScopeMismatch, ErrExpired for a Pending expired at or before
// s.Now, whatever the kind, and ErrInvalidRecord for a Pending open refuses or any other missing or
// malformed field.
func NewRecord(s Spec, open PendingOpener) (Record, error) {
	if !s.Kind.Valid() {
		return Record{}, errors.Join(ErrInvalidRecord, errors.New("invalid kind"))
	}
	if s.Kind.Stateless() {
		return Record{}, ErrStatelessKind
	}
	if open == nil || s.Pending.IsZero() {
		return Record{}, errors.Join(ErrInvalidRecord, errors.New("sealed pending and its opener are required"))
	}
	b, err := open(s.Pending)
	if err != nil {
		return Record{}, errors.Join(ErrInvalidRecord, err)
	}
	if s.Scope.class != s.Kind.Scope() || !bindingFits(s.Scope, b) {
		return Record{}, ErrScopeMismatch
	}
	if s.Now.IsZero() || b.ExpiresAt.IsZero() {
		return Record{}, errors.Join(ErrInvalidRecord, errors.New("writing time and pending expiry are required"))
	}
	end := s.Kind.ExpiresAt(b.ExpiresAt, s.Now)
	if !b.ExpiresAt.After(s.Now) || !end.After(s.Now) {
		return Record{}, ErrExpired
	}
	return Restore(Row{
		Tenant:     b.Tenant,
		Kind:       s.Kind,
		HandleHash: s.HandleHash,
		ScopeHash:  s.Scope.hash,
		Pending:    s.Pending,
		Payload:    s.Payload,
		ExpiresAt:  end,
		CreatedAt:  s.Now,
	})
}

// Restore rebuilds a record read back from storage. Only store implementations may call it (G6). It
// returns the errors of NewRecord for a row that NewRecord could not have produced.
func Restore(r Row) (Record, error) {
	if err := checkRow(r); err != nil {
		return Record{}, err
	}
	return Record{
		Pending:    principal.SealedFromBytes(r.Pending.Bytes()),
		pending:    r.Pending.Bytes(),
		tenant:     r.Tenant,
		kind:       r.Kind,
		handleHash: slices.Clone(r.HandleHash),
		scopeHash:  slices.Clone(r.ScopeHash),
		payload:    slices.Clone(r.Payload),
		attempts:   r.Attempts,
		expiresAt:  r.ExpiresAt,
		createdAt:  r.CreatedAt,
	}, nil
}

func checkRow(r Row) error {
	if !r.Kind.Valid() {
		return errors.Join(ErrInvalidRecord, errors.New("invalid kind"))
	}
	if r.Kind.Stateless() {
		return ErrStatelessKind
	}
	if len(r.HandleHash) < HandleHashLen {
		return ErrHandleTooShort
	}
	if !scopeHashFits(r.Kind.Scope(), r.ScopeHash) {
		return ErrScopeMismatch
	}
	var problem string
	switch {
	case len(r.HandleHash) > MaxHandleHashLen:
		problem = "handle hash is too long"
	case r.Pending.IsZero():
		problem = "sealed pending is required"
	case len(r.Payload) > MaxPayloadLen:
		problem = "payload is too large"
	case r.Attempts < 0 || r.Attempts >= r.Kind.MaxAttempts():
		problem = "attempts are outside the kind's bound"
	case r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt):
		problem = "expiry must fall after creation"
	case r.ExpiresAt.After(r.CreatedAt.Add(r.Kind.TTL())):
		problem = "expiry exceeds the kind's lifetime"
	default:
		return nil
	}
	return errors.Join(ErrInvalidRecord, errors.New(problem))
}

func bindingFits(s Scope, b PendingBinding) bool {
	if !b.Subject.IsZero() && b.Subject.Tenant != b.Tenant {
		return false
	}
	if s.class != Subject {
		return true
	}
	if s.tenant != b.Tenant {
		return false
	}
	return b.Subject.IsZero() || bytes.Equal(s.hash, b.Subject.User[:])
}

func scopeHashFits(c ScopeClass, h []byte) bool {
	switch c {
	case Subject:
		return len(h) == len(uuid.UUID{}) && uuid.UUID(h) != uuid.Nil
	case Identifier:
		return len(h) == IdentifierScopeLen
	}
	return false
}

// Validate returns the error Restore would return for r, and ErrInvalidRecord once its Pending was
// replaced; Put calls it so that a Record literal, which cannot set the index fields, is refused.
func (r Record) Validate() error {
	if !bytes.Equal(r.Pending.Bytes(), r.pending) {
		return errors.Join(ErrInvalidRecord, errors.New("sealed pending was replaced after construction"))
	}
	return checkRow(Row{
		Tenant:     r.tenant,
		Kind:       r.kind,
		HandleHash: r.handleHash,
		ScopeHash:  r.scopeHash,
		Pending:    r.Pending,
		Payload:    r.payload,
		Attempts:   r.attempts,
		ExpiresAt:  r.expiresAt,
		CreatedAt:  r.createdAt,
	})
}

func (r Record) Tenant() principal.TenantID { return r.tenant }

func (r Record) Kind() Kind { return r.kind }

// HandleHash returns the digest of the 256-bit handle the record is looked up by.
func (r Record) HandleHash() []byte { return slices.Clone(r.handleHash) }

// ScopeHash returns the subject id or identifier HMAC the record is capped and deleted by.
func (r Record) ScopeHash() []byte { return slices.Clone(r.scopeHash) }

// ScopedTo reports whether r was written for scope s: same class and hash and, for a subject scope,
// same tenant. A subject-scoped short-code record (authenticated phone verification) is still found
// by its random handle (C-30); the caller then requires ScopedTo(SubjectScope(session subject))
// before comparing the code, so a handle never serves another subject.
func (r Record) ScopedTo(s Scope) bool {
	if s.class == 0 || s.class != r.kind.Scope() || !bytes.Equal(s.hash, r.scopeHash) {
		return false
	}
	return s.class != Subject || s.tenant == r.tenant
}

// Payload returns the encoded typed payload (internal/ceremonycodec).
func (r Record) Payload() []byte { return slices.Clone(r.payload) }

// Attempts returns the failed verifications charged so far; the record is deleted at
// Kind.MaxAttempts.
func (r Record) Attempts() int { return r.attempts }

// ExpiresAt returns when the record stops being usable. For a session-admitting kind it never
// exceeds the Pending's expiry; other kinds (PasswordReset, EmailVerification, SecurityRevert...)
// deliberately outlive their Pending, whose expiry then bounds only the session it might admit.
func (r Record) ExpiresAt() time.Time { return r.expiresAt }

// CreatedAt returns when the record was written; Put evicts the oldest first.
func (r Record) CreatedAt() time.Time { return r.createdAt }
