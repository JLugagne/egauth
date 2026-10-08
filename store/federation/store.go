// Package federation holds the persistence contract of per-tenant OAuth and OIDC provider specs and
// of the identities linked to them. Stores keep the sealed client secret as opaque bytes and never
// see a KEK.
package federation

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

const (
	// AADVersionLegacy marks a secret sealed by v0.16, before associated data was mandatory.
	AADVersionLegacy uint8 = 0
	// AADVersionCurrent marks a secret sealed under the v0.17 format.
	AADVersionCurrent uint8 = 1
)

// ErrLegacyAADVersion reports a provider written with an AADVersion other than AADVersionCurrent:
// v0.16 secrets are only ever read and re-sealed, never written fresh, so startup never meets a new
// v0 row (C-58).
var ErrLegacyAADVersion = errors.New("federation: new secrets must use AADVersionCurrent")

// EmailVerification tells how far a provider's email claim is trusted. Its value is persisted
// (email_verification SMALLINT) and never renumbered; the zero value is the safest.
type EmailVerification uint8

const (
	// Never ignores the provider's email claim.
	Never EmailVerification = 0
	// ClaimBased trusts the email_verified claim, for emails of the spec's Domains only.
	ClaimBased EmailVerification = 1
	// Always trusts every email the provider returns; only for providers egauth knows to verify.
	Always EmailVerification = 2
)

// Valid reports whether v is a declared value.
func (v EmailVerification) Valid() bool { return v <= Always }

// String returns the lowercase name of v, or "invalid".
func (v EmailVerification) String() string {
	switch v {
	case Never:
		return "never"
	case ClaimBased:
		return "claim_based"
	case Always:
		return "always"
	}
	return "invalid"
}

// ProviderSpec is the persisted spec of one provider of a tenant. Domains may be set only by a
// system caller.
type ProviderSpec struct {
	Tenant            principal.TenantID
	Name              string
	ClientID          string
	SealedSecret      []byte
	AADVersion        uint8
	AuthURL           string
	TokenURL          string
	UserInfoURL       string
	Scopes            []string
	Issuer            string
	JWKSURL           string
	Domains           []string
	EmailVerification EmailVerification
	UpdatedAt         time.Time
}

// LinkKey addresses a linked identity by the provider's own subject.
type LinkKey struct {
	Provider        string
	ProviderSubject string
}

// LinkedIdentity is the link between a subject and a provider account. ProviderEmail is the email
// as the provider returned it; it never becomes the account email by itself (C-05).
type LinkedIdentity struct {
	Subject               principal.Subject
	Key                   LinkKey
	ProviderEmail         string
	ProviderEmailVerified bool
	LinkedAt              time.Time
}

// SealedRef addresses the sealed client secret of one provider.
type SealedRef struct {
	Tenant   principal.TenantID
	Provider string
}

// V016Row is a v0.16-sealed provider secret awaiting upgrade.
type V016Row struct {
	Ref    SealedRef
	Sealed []byte
}

// Reseal is the compare-and-swap of a sealed client secret: Old is the exact sealed bytes that were
// read, so a secret an administrator replaced in the meantime is never overwritten.
type Reseal struct {
	Ref SealedRef
	Old []byte
	New []byte
}

// Store persists provider specs and reads linked identities. Links are written through the identity
// store's LinkFederated and UnlinkFederated mutations, in the same transaction as the epoch bump.
type Store interface {
	store.Base

	// PutProvider inserts or replaces the spec of (Tenant, Name). It returns ErrLegacyAADVersion when
	// p.AADVersion is not AADVersionCurrent.
	PutProvider(ctx context.Context, p ProviderSpec) error
	// GetProvider returns the spec, or store.ErrNotFound.
	GetProvider(ctx context.Context, t principal.TenantID, name string) (ProviderSpec, error)
	// ListProviders returns every spec of the tenant.
	ListProviders(ctx context.Context, t principal.TenantID) ([]ProviderSpec, error)
	// DeleteProvider removes the spec. It is idempotent.
	DeleteProvider(ctx context.Context, t principal.TenantID, name string) error

	// FindLinked returns the identity linked to the provider account, or store.ErrNotFound.
	FindLinked(ctx context.Context, t principal.TenantID, k LinkKey) (LinkedIdentity, error)
	// LinkedFor returns every identity linked to the subject.
	LinkedFor(ctx context.Context, s principal.Subject) ([]LinkedIdentity, error)
	// DeleteForSubject removes every link of the subject. It is idempotent.
	DeleteForSubject(ctx context.Context, s principal.Subject) error

	// CountLegacySealed returns how many provider secrets still have aad_version 0.
	CountLegacySealed(ctx context.Context) (int64, error)
	// V016Sealed returns up to limit aad_version 0 providers after the cursor, with the cursor of
	// the last one. The zero cursor starts from the beginning. DESIGN section 4.7 calls it
	// LegacySealed(cursor).
	V016Sealed(ctx context.Context, after store.Cursor, limit int) ([]V016Row, store.Cursor, error)
	// ReplaceSealed stores r.New and sets aad_version to AADVersionCurrent only while the stored
	// sealed bytes still equal r.Old, and reports whether it did. It serves both the v0.16 upgrade
	// and the lazy re-seal after a KEK rotation, and changes no other field of the spec.
	ReplaceSealed(ctx context.Context, r Reseal) (bool, error)
}
