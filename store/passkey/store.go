// Package passkey holds the persistence contract of WebAuthn credentials.
package passkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

// MaxCredentialIDLen is the WebAuthn bound on a credential id, in bytes.
const MaxCredentialIDLen = 1023

// CredentialID is a raw WebAuthn credential id. It encodes to JSON as an unpadded base64url string,
// so the same text is used on the wire and in logs (P-05).
type CredentialID []byte

// String returns the unpadded base64url form.
func (c CredentialID) String() string { return base64.RawURLEncoding.EncodeToString(c) }

// MarshalJSON encodes c as an unpadded base64url string, and an empty id as null so that
// UnmarshalJSON reads it back.
func (c CredentialID) MarshalJSON() ([]byte, error) {
	if len(c) == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(c.String())
}

// UnmarshalJSON decodes a non-empty unpadded base64url string of at most MaxCredentialIDLen bytes
// and refuses any other alphabet or padding. null leaves c unchanged.
func (c *CredentialID) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.Join(errors.New("passkey: credential id must be a string"), err)
	}
	if s == "" {
		return errors.New("passkey: credential id is empty")
	}
	if len(s) > base64.RawURLEncoding.EncodedLen(MaxCredentialIDLen) {
		return errors.New("passkey: credential id is too long")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return errors.Join(errors.New("passkey: credential id is not unpadded base64url"), err)
	}
	*c = raw
	return nil
}

// Equal compares ids byte for byte; a nil and an empty id are equal.
func (c CredentialID) Equal(o CredentialID) bool { return slices.Equal(c, o) }

// DiscoverableState tells whether a credential is known to be resident. Its value is persisted
// (discoverable SMALLINT) and never renumbered.
type DiscoverableState uint8

const (
	// Legacy is reserved for v0.16 rows, registered before residency was required.
	Legacy DiscoverableState = 0
	// Confirmed means credProps.rk was true at registration.
	Confirmed DiscoverableState = 1
	// Inferred means credProps was absent, and residency follows from the required resident key.
	Inferred DiscoverableState = 2
)

// Valid reports whether d is a declared state.
func (d DiscoverableState) Valid() bool { return d <= Inferred }

// String returns the lowercase name of d, or "invalid".
func (d DiscoverableState) String() string {
	switch d {
	case Legacy:
		return "legacy"
	case Confirmed:
		return "confirmed"
	case Inferred:
		return "inferred"
	}
	return "invalid"
}

// NeedsReregistration reports whether the credential predates residency and should be replaced.
func (d DiscoverableState) NeedsReregistration() bool { return d == Legacy }

// Credential is one registered WebAuthn credential. A suspended credential is refused at login and
// step-up but never deleted. Its JSON form is the user-facing listing: the subject, the public key,
// the sign counter and the authenticator data are never encoded (P-05).
type Credential struct {
	Subject        principal.Subject `json:"-"`
	ID             CredentialID      `json:"id"`
	PublicKey      []byte            `json:"-"`
	SignCount      uint32            `json:"-"`
	Data           []byte            `json:"-"`
	CreatedAt      time.Time         `json:"created_at"`
	Nickname       string            `json:"nickname"`
	LastUsedAt     *time.Time        `json:"last_used_at,omitempty"`
	Transports     []string          `json:"transports,omitempty"`
	BackupEligible bool              `json:"backup_eligible"`
	BackupState    bool              `json:"backup_state"`
	Discoverable   DiscoverableState `json:"discoverable"`
	SuspendedAt    *time.Time        `json:"suspended_at,omitempty"`
}

// Active reports whether the credential may authenticate.
func (c Credential) Active() bool { return c.SuspendedAt == nil }

// AcceptsSignCount is the WebAuthn L3 section 7.2 counter rule shared by every Store, against the
// stored SignCount: next is accepted when it is greater, or when both are zero (an authenticator
// without a counter). Any other next, a zero one against a non-zero SignCount included, is the clone
// signal of P-12.
func (c Credential) AcceptsSignCount(next uint32) bool {
	return next > c.SignCount || (c.SignCount == 0 && next == 0)
}

// Store persists credentials. Credential ids are unique per tenant. It embeds no store.Reaper:
// credentials carry no expiry, so its storetest asserts store.Base only.
type Store interface {
	store.Base

	// Save persists a new credential, or returns store.ErrConflict when the id exists in the tenant.
	Save(ctx context.Context, c Credential) error
	// List returns every credential of the subject, suspended ones included.
	List(ctx context.Context, s principal.Subject) ([]Credential, error)
	// Get returns a credential by id, or store.ErrNotFound. Discoverable logins resolve the
	// credential this way, never through a stored flag.
	Get(ctx context.Context, t principal.TenantID, id CredentialID) (Credential, error)
	// Update persists the metadata of an existing credential (nickname, last use, backup flags,
	// discoverable state). It matches (c.Subject, c.ID), returns store.ErrNotFound otherwise, and
	// never changes PublicKey, Subject, ID, SignCount or SuspendedAt.
	Update(ctx context.Context, c Credential) error
	// UpdateSignCount atomically stores next while AcceptsSignCount(next) holds for the stored
	// credential, and reports whether it did; it returns store.ErrNotFound when the credential is
	// absent. The condition is evaluated on the stored counter, never on the value read, so a
	// ceremony whose counter beats the one a concurrent ceremony just stored succeeds. A false result
	// is always the clone signal of P-12, a zero next against a non-zero stored counter included;
	// only zero against zero is a counterless authenticator, which reports true.
	UpdateSignCount(ctx context.Context, s principal.Subject, id CredentialID, next uint32) (bool, error)
	// Suspend sets SuspendedAt to at unless already set. It returns store.ErrNotFound when absent.
	Suspend(ctx context.Context, s principal.Subject, id CredentialID, at time.Time) error
	// Delete removes one credential of the subject, or returns store.ErrNotFound.
	Delete(ctx context.Context, s principal.Subject, id CredentialID) error
	// HasActive reports whether the subject has a credential that is not suspended.
	HasActive(ctx context.Context, s principal.Subject) (bool, error)
	// AnyEnrolled reports whether any subject of any tenant has a credential, suspended or not. New
	// refuses to start on true while the passkey module is absent (C-01).
	AnyEnrolled(ctx context.Context) (bool, error)
	// CountEnrolled returns how many subjects of all tenants AnyEnrolled counts, for the message of
	// that startup refusal.
	CountEnrolled(ctx context.Context) (int64, error)
	// DeleteForSubject removes every credential of the subject. It is idempotent.
	DeleteForSubject(ctx context.Context, s principal.Subject) error
}
