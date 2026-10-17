package sessions

import (
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
)

const maxClockSkew = time.Minute

// HashLen is the length of the session token digest a record is keyed by: the SHA-256 digest of a
// 256-bit random token.
const HashLen = 32

// MaxFingerprintLen bounds the client fingerprint stored on a session, in bytes.
const MaxFingerprintLen = 64

// MaxAppClaimsLen bounds the encoded application claims stored next to a session, in bytes.
const MaxAppClaimsLen = 16 << 10

// AttrsSealer seals session attributes; callers pass the core codec (core.Seal). NewRecord seals
// the very attributes it derives the index fields from, so the two cannot disagree (C-64).
type AttrsSealer func(principal.SessionAttrs) (principal.Sealed, error)

// Spec describes a stateful session row to write. The index fields and the sealed value both come
// from Attrs. Now is the writing instant from the library clock; it is also the instant Renew last
// checked the attributes.
type Spec struct {
	ID                uuid.UUID
	TokenHash         []byte
	Attrs             principal.SessionAttrs
	AppClaims         []byte
	ClientFingerprint []byte
	IdleTTL           time.Duration
	MaxLifetime       time.Duration
	Now               time.Time
}

// Record is one stateful session row. Its tenant, subject, lineage, epoch and absolute expiry are
// derived from the sealed session, never set independently; build it with NewRecord, or Restore in
// a store implementation.
type Record struct {
	id                uuid.UUID
	tokenHash         []byte
	subject           principal.Subject
	lineage           uuid.UUID
	sealed            principal.Sealed
	appClaims         []byte
	epoch             uint64
	clientFingerprint []byte
	idleExpiresAt     time.Time
	absoluteExpiresAt time.Time
	checkedAt         time.Time
	createdAt         time.Time
}

// Row is the persisted shape of a Record, for store implementations.
type Row struct {
	ID                uuid.UUID
	TokenHash         []byte
	Subject           principal.Subject
	Lineage           uuid.UUID
	Sealed            principal.Sealed
	AppClaims         []byte
	SecurityEpoch     uint64
	ClientFingerprint []byte
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	CheckedAt         time.Time
	CreatedAt         time.Time
}

// NewRecord derives the index fields from s.Attrs and seals s.Attrs with seal: the session ends
// MaxLifetime after the lineage was admitted, and idles out IdleTTL after s.Now but never after that
// end. It returns ErrInvalidRecord for a missing or malformed field, a sealing failure or an s.Now
// more than a minute before the lineage was admitted (a wrong clock), and ErrLifetimeExceeded once
// the lineage has outlived MaxLifetime.
func NewRecord(s Spec, seal AttrsSealer) (Record, error) {
	if s.Attrs.IsZero() || s.Attrs.CreatedAt().IsZero() {
		return Record{}, errors.Join(ErrInvalidRecord, errors.New("session attributes are not set"))
	}
	if seal == nil {
		return Record{}, errors.Join(ErrInvalidRecord, errors.New("a sealer is required"))
	}
	if s.IdleTTL <= 0 || s.MaxLifetime <= 0 || s.Now.IsZero() {
		return Record{}, errors.Join(ErrInvalidRecord, errors.New("lifetimes and writing time are required"))
	}
	if s.Now.Before(s.Attrs.CreatedAt().Add(-maxClockSkew)) {
		return Record{}, errors.Join(ErrInvalidRecord, errors.New("writing time precedes the lineage admission"))
	}
	end := s.Attrs.CreatedAt().Add(s.MaxLifetime)
	if !s.Now.Before(end) {
		return Record{}, ErrLifetimeExceeded
	}
	idle := s.Now.Add(s.IdleTTL)
	if idle.After(end) {
		idle = end
	}
	sealed, err := seal(s.Attrs)
	if err != nil {
		return Record{}, errors.Join(ErrInvalidRecord, err)
	}
	return Restore(Row{
		ID:                s.ID,
		TokenHash:         s.TokenHash,
		Subject:           s.Attrs.Subject(),
		Lineage:           s.Attrs.Lineage(),
		Sealed:            sealed,
		AppClaims:         s.AppClaims,
		SecurityEpoch:     s.Attrs.Epoch(),
		ClientFingerprint: s.ClientFingerprint,
		IdleExpiresAt:     idle,
		AbsoluteExpiresAt: end,
		CheckedAt:         s.Now,
		CreatedAt:         s.Now,
	})
}

// Restore rebuilds a record read back from storage. Only store implementations may call it (G6).
// It returns ErrInvalidRecord for a row that NewRecord could not have produced.
func Restore(r Row) (Record, error) {
	if err := checkRow(r); err != nil {
		return Record{}, errors.Join(ErrInvalidRecord, err)
	}
	return Record{
		id:                r.ID,
		tokenHash:         slices.Clone(r.TokenHash),
		subject:           r.Subject,
		lineage:           r.Lineage,
		sealed:            principal.SealedFromBytes(r.Sealed.Bytes()),
		appClaims:         slices.Clone(r.AppClaims),
		epoch:             r.SecurityEpoch,
		clientFingerprint: slices.Clone(r.ClientFingerprint),
		idleExpiresAt:     r.IdleExpiresAt,
		absoluteExpiresAt: r.AbsoluteExpiresAt,
		checkedAt:         r.CheckedAt,
		createdAt:         r.CreatedAt,
	}, nil
}

func checkRow(r Row) error {
	switch {
	case r.ID == uuid.Nil || r.Lineage == uuid.Nil:
		return errors.New("id and lineage are required")
	case len(r.TokenHash) != HashLen:
		return errors.New("token hash must be a SHA-256 digest")
	case r.Subject.IsZero():
		return errors.New("subject is required")
	case r.Sealed.IsZero():
		return errors.New("sealed session attributes are required")
	case len(r.AppClaims) > MaxAppClaimsLen:
		return errors.New("application claims are too large")
	case len(r.ClientFingerprint) > MaxFingerprintLen:
		return errors.New("client fingerprint is too long")
	case r.CreatedAt.IsZero() || r.CheckedAt.IsZero() || r.IdleExpiresAt.IsZero() || r.AbsoluteExpiresAt.IsZero():
		return errors.New("creation, check and expiry times are required")
	case r.CreatedAt.After(r.AbsoluteExpiresAt) || r.CheckedAt.Before(r.CreatedAt.Add(-maxClockSkew)):
		return errors.New("creation must not follow the absolute expiry and the last check must not precede creation")
	case !r.IdleExpiresAt.After(r.CheckedAt) || r.IdleExpiresAt.After(r.AbsoluteExpiresAt):
		return errors.New("idle expiry must fall after the last check and within the absolute lifetime")
	}
	return nil
}

// ID returns the row id, which Rotate keeps and Replace changes.
func (r Record) ID() uuid.UUID { return r.id }

// TokenHash returns the SHA-256 digest of the session token, the lookup key.
func (r Record) TokenHash() []byte { return slices.Clone(r.tokenHash) }

func (r Record) Tenant() principal.TenantID { return r.subject.Tenant }

func (r Record) Subject() principal.Subject { return r.subject }

// Lineage returns the session id sealed in the attributes, stable across Rotate and Replace.
func (r Record) Lineage() uuid.UUID { return r.lineage }

// Sealed returns the sealed session attributes, kept verbatim.
func (r Record) Sealed() principal.Sealed { return principal.SealedFromBytes(r.sealed.Bytes()) }

// AppClaims returns the encoded application claims fetched with the attributes.
func (r Record) AppClaims() []byte { return slices.Clone(r.appClaims) }

// Epoch returns the subject's security epoch sealed in the attributes.
func (r Record) Epoch() uint64 { return r.epoch }

// ClientFingerprint returns the fingerprint of the client the session was written for.
func (r Record) ClientFingerprint() []byte { return slices.Clone(r.clientFingerprint) }

// IdleExpiresAt returns when the session idles out unless touched.
func (r Record) IdleExpiresAt() time.Time { return r.idleExpiresAt }

// AbsoluteExpiresAt returns the end of the lineage (MaxLifetime from its admission); Touch never
// extends a session past it.
func (r Record) AbsoluteExpiresAt() time.Time { return r.absoluteExpiresAt }

// CheckedAt returns when Renew last re-read account state and claims for this session.
func (r Record) CheckedAt() time.Time { return r.checkedAt }

// CreatedAt returns when the row was written.
func (r Record) CreatedAt() time.Time { return r.createdAt }

// IsZero reports whether r was built by neither NewRecord nor Restore; stores refuse such a record
// with ErrInvalidRecord.
func (r Record) IsZero() bool { return r.id == uuid.Nil }
