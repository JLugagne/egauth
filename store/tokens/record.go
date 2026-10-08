package tokens

import (
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
)

const maxClockSkew = time.Minute

// HashLen is the length of every handle hash a tokens record is keyed by: the SHA-256 digest of a
// 256-bit random handle. A shorter value cannot be a hash of such a handle and is refused.
const HashLen = 32

// MaxFingerprintLen bounds the client fingerprint persisted for reuse detection (T-21), in bytes.
const MaxFingerprintLen = 64

// MaxAppClaimsLen bounds the encoded application claims stored next to a record, in bytes.
const MaxAppClaimsLen = 16 << 10

// AttrsSealer seals session attributes; callers pass the core codec (core.Seal). NewRefreshRecord
// seals the very attributes it derives the index fields from, so the two cannot disagree (C-64).
type AttrsSealer func(principal.SessionAttrs) (principal.Sealed, error)

// RefreshSpec describes a refresh token to issue. The index fields and the sealed value both come
// from Attrs. Now is the issuing instant from the library clock.
type RefreshSpec struct {
	TokenHash         []byte
	Family            uuid.UUID
	Attrs             principal.SessionAttrs
	AppClaims         []byte
	ClientFingerprint []byte
	IdleTTL           time.Duration
	MaxLifetime       time.Duration
	Now               time.Time
}

// RefreshRecord is one refresh token of a family. Its tenant, subject, lineage, epoch and expiry
// index fields are derived from the sealed session, never set independently; build it with
// NewRefreshRecord, or RestoreRefreshRecord in a store implementation.
type RefreshRecord struct {
	tokenHash         []byte
	family            uuid.UUID
	subject           principal.Subject
	lineage           uuid.UUID
	sealed            principal.Sealed
	appClaims         []byte
	epoch             uint64
	clientFingerprint []byte
	idleExpiresAt     time.Time
	familyExpiresAt   time.Time
	createdAt         time.Time
}

// RefreshRow is the persisted shape of a RefreshRecord, for store implementations.
type RefreshRow struct {
	TokenHash         []byte
	Family            uuid.UUID
	Subject           principal.Subject
	Lineage           uuid.UUID
	Sealed            principal.Sealed
	AppClaims         []byte
	SecurityEpoch     uint64
	ClientFingerprint []byte
	IdleExpiresAt     time.Time
	FamilyExpiresAt   time.Time
	CreatedAt         time.Time
}

// NewRefreshRecord derives the index fields from s.Attrs and seals s.Attrs with seal: the family
// expires MaxLifetime after the lineage was admitted, and the token expires IdleTTL after s.Now but
// never after its family. It returns ErrInvalidRecord for a missing or malformed field, a sealing
// failure or an s.Now more than a minute before the lineage was admitted (a wrong clock), and
// ErrLifetimeExceeded once the lineage has outlived MaxLifetime.
func NewRefreshRecord(s RefreshSpec, seal AttrsSealer) (RefreshRecord, error) {
	if s.Attrs.IsZero() || s.Attrs.CreatedAt().IsZero() {
		return RefreshRecord{}, errors.Join(ErrInvalidRecord, errors.New("session attributes are not set"))
	}
	if seal == nil {
		return RefreshRecord{}, errors.Join(ErrInvalidRecord, errors.New("a sealer is required"))
	}
	if s.IdleTTL <= 0 || s.MaxLifetime <= 0 || s.Now.IsZero() {
		return RefreshRecord{}, errors.Join(ErrInvalidRecord, errors.New("lifetimes and issuing time are required"))
	}
	if s.Now.Before(s.Attrs.CreatedAt().Add(-maxClockSkew)) {
		return RefreshRecord{}, errors.Join(ErrInvalidRecord, errors.New("issuing time precedes the lineage admission"))
	}
	familyEnd := s.Attrs.CreatedAt().Add(s.MaxLifetime)
	if !s.Now.Before(familyEnd) {
		return RefreshRecord{}, ErrLifetimeExceeded
	}
	idleEnd := s.Now.Add(s.IdleTTL)
	if idleEnd.After(familyEnd) {
		idleEnd = familyEnd
	}
	sealed, err := seal(s.Attrs)
	if err != nil {
		return RefreshRecord{}, errors.Join(ErrInvalidRecord, err)
	}
	return RestoreRefreshRecord(RefreshRow{
		TokenHash:         s.TokenHash,
		Family:            s.Family,
		Subject:           s.Attrs.Subject(),
		Lineage:           s.Attrs.Lineage(),
		Sealed:            sealed,
		AppClaims:         s.AppClaims,
		SecurityEpoch:     s.Attrs.Epoch(),
		ClientFingerprint: s.ClientFingerprint,
		IdleExpiresAt:     idleEnd,
		FamilyExpiresAt:   familyEnd,
		CreatedAt:         s.Now,
	})
}

// RestoreRefreshRecord rebuilds a record read back from storage. Only store implementations may call
// it (G6). It returns ErrInvalidRecord for a row that NewRefreshRecord could not have produced.
func RestoreRefreshRecord(r RefreshRow) (RefreshRecord, error) {
	if err := checkRefreshRow(r); err != nil {
		return RefreshRecord{}, errors.Join(ErrInvalidRecord, err)
	}
	return RefreshRecord{
		tokenHash:         slices.Clone(r.TokenHash),
		family:            r.Family,
		subject:           r.Subject,
		lineage:           r.Lineage,
		sealed:            principal.SealedFromBytes(r.Sealed.Bytes()),
		appClaims:         slices.Clone(r.AppClaims),
		epoch:             r.SecurityEpoch,
		clientFingerprint: slices.Clone(r.ClientFingerprint),
		idleExpiresAt:     r.IdleExpiresAt,
		familyExpiresAt:   r.FamilyExpiresAt,
		createdAt:         r.CreatedAt,
	}, nil
}

func checkRefreshRow(r RefreshRow) error {
	switch {
	case len(r.TokenHash) != HashLen:
		return errors.New("token hash must be a SHA-256 digest")
	case r.Family == uuid.Nil || r.Lineage == uuid.Nil:
		return errors.New("family and lineage are required")
	case r.Subject.IsZero():
		return errors.New("subject is required")
	case r.Sealed.IsZero():
		return errors.New("sealed session attributes are required")
	case len(r.AppClaims) > MaxAppClaimsLen:
		return errors.New("application claims are too large")
	case len(r.ClientFingerprint) > MaxFingerprintLen:
		return errors.New("client fingerprint is too long")
	case r.CreatedAt.IsZero() || r.IdleExpiresAt.IsZero() || r.FamilyExpiresAt.IsZero():
		return errors.New("creation and expiry times are required")
	case !r.IdleExpiresAt.After(r.CreatedAt) || r.IdleExpiresAt.After(r.FamilyExpiresAt):
		return errors.New("idle expiry must fall after creation and within the family lifetime")
	}
	return nil
}

// TokenHash returns the SHA-256 digest of the refresh token, the record's key.
func (r RefreshRecord) TokenHash() []byte { return slices.Clone(r.tokenHash) }

// Family returns the family id (the access token sid); Reissue starts a new family on the same
// lineage.
func (r RefreshRecord) Family() uuid.UUID { return r.family }

func (r RefreshRecord) Tenant() principal.TenantID { return r.subject.Tenant }

func (r RefreshRecord) Subject() principal.Subject { return r.subject }

// Lineage returns the session id sealed in the attributes, stable across rotation and Reissue.
func (r RefreshRecord) Lineage() uuid.UUID { return r.lineage }

// Sealed returns the sealed session attributes, kept verbatim.
func (r RefreshRecord) Sealed() principal.Sealed { return principal.SealedFromBytes(r.sealed.Bytes()) }

// AppClaims returns the encoded application claims fetched with the attributes.
func (r RefreshRecord) AppClaims() []byte { return slices.Clone(r.appClaims) }

// Epoch returns the subject's security epoch sealed in the attributes.
func (r RefreshRecord) Epoch() uint64 { return r.epoch }

// ClientFingerprint returns the fingerprint of the client the token was issued to; a store records
// it as consumed_by on the token it replaces.
func (r RefreshRecord) ClientFingerprint() []byte { return slices.Clone(r.clientFingerprint) }

// IdleExpiresAt returns when this token stops being accepted.
func (r RefreshRecord) IdleExpiresAt() time.Time { return r.idleExpiresAt }

// FamilyExpiresAt returns the absolute end of the lineage (MaxLifetime from its admission).
func (r RefreshRecord) FamilyExpiresAt() time.Time { return r.familyExpiresAt }

// CreatedAt returns when the token was issued.
func (r RefreshRecord) CreatedAt() time.Time { return r.createdAt }

// IsZero reports whether r was built by neither NewRefreshRecord nor RestoreRefreshRecord; stores
// refuse such a record with ErrInvalidRecord.
func (r RefreshRecord) IsZero() bool { return len(r.tokenHash) == 0 }
