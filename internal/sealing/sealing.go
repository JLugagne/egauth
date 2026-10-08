// Package sealing is the only caller of kek.KEK Seal and Open (G6) and the only place the
// associated data of a sealed secret is computed. The AAD binds a ciphertext to its purpose, tenant
// and row: "egauth/<kind>/v1\x00" + tenant + "\x00" + id, or "egauth/<kind>/v1\x00" + id for
// deployment-wide secrets. Open reports a ciphertext sealed by a non-current key as stale so the
// caller re-seals it and writes it back through the store's ReplaceSealed CAS (lazy rotation).
package sealing

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
)

type kind uint8

const (
	kindTOTP kind = iota + 1
	kindOAuthClientSecret
	kindSigningKey
	kindDataKey
)

func (k kind) name() string {
	switch k {
	case kindTOTP:
		return "totp"
	case kindOAuthClientSecret:
		return "oauth-client-secret"
	case kindSigningKey:
		return "signing-key"
	case kindDataKey:
		return "deployment"
	}
	return ""
}

const maxIDLen = 256

var (
	// ErrInvalidRef is returned by the Ref constructors for an empty or malformed identifier, and
	// by Seal, Open and OpenLegacy for the zero Ref.
	ErrInvalidRef = errors.New("sealing: invalid reference")
	// ErrNoLegacyFormat is returned by OpenLegacy for a secret that v0.16 never sealed.
	ErrNoLegacyFormat = errors.New("sealing: secret has no v0.16 format")
	// ErrLegacyUnopenable is returned by OpenLegacy when no candidate legacy AAD opens the blob.
	ErrLegacyUnopenable = errors.New("sealing: v0.16 blob opens under no candidate associated data")
)

// Ref names one sealed secret: its purpose, tenant and row. It is built only by the constructors
// below; the zero Ref is refused everywhere.
type Ref struct {
	kind   kind
	tenant principal.TenantID
	id     string
}

// TOTPSecret names the TOTP seed of s. It returns ErrInvalidRef for a zero subject.
func TOTPSecret(s principal.Subject) (Ref, error) {
	if s.User == uuid.Nil {
		return Ref{}, ErrInvalidRef
	}
	return Ref{kind: kindTOTP, tenant: s.Tenant, id: s.User.String()}, nil
}

// OAuthClientSecret names the client secret of a tenant's OAuth or OIDC provider. It returns
// ErrInvalidRef for an empty, oversized or NUL-bearing provider name.
func OAuthClientSecret(t principal.TenantID, provider string) (Ref, error) {
	if err := checkID(provider); err != nil {
		return Ref{}, err
	}
	return Ref{kind: kindOAuthClientSecret, tenant: t, id: provider}, nil
}

// SigningKey names the private material of a tenant signing key. It returns ErrInvalidRef for an
// empty, oversized or NUL-bearing key id.
func SigningKey(t principal.TenantID, kid string) (Ref, error) {
	if err := checkID(kid); err != nil {
		return Ref{}, err
	}
	return Ref{kind: kindSigningKey, tenant: t, id: kid}, nil
}

// DataKey names the deployment data key. Its AAD is "egauth/deployment/v1\x00datakey".
func DataKey() Ref {
	return Ref{kind: kindDataKey, id: "datakey"}
}

func checkID(id string) error {
	if id == "" || len(id) > maxIDLen || strings.ContainsRune(id, 0) {
		return ErrInvalidRef
	}
	return nil
}

// AAD returns the associated data r binds, for diagnostics and fixtures. It returns nil for the
// zero Ref.
func (r Ref) AAD() kek.AAD {
	name := r.kind.name()
	if name == "" {
		return nil
	}
	var b bytes.Buffer
	b.WriteString("egauth/" + name + "/v1\x00")
	if r.kind != kindDataKey {
		b.WriteString(r.tenant.String())
		b.WriteByte(0)
	}
	b.WriteString(r.id)
	return kek.AAD(b.Bytes())
}

// String renders the purpose, tenant and row; a Ref holds no secret.
func (r Ref) String() string {
	return "sealing.Ref{" + r.kind.name() + " tenant=" + strconv.Quote(r.tenant.String()) + " id=" + strconv.Quote(r.id) + "}"
}

// Opened is the result of Open. Stale reports that the ciphertext was sealed by a key other than
// the KEK's current one; the caller re-seals Plaintext and writes it back with a CAS.
type Opened struct {
	Plaintext []byte
	Stale     bool
}

// String redacts Plaintext.
func (o Opened) String() string {
	return "sealing.Opened{Plaintext: REDACTED, Stale: " + strconv.FormatBool(o.Stale) + "}"
}

// GoString redacts Plaintext like String.
func (o Opened) GoString() string { return o.String() }

// LogValue redacts Plaintext like String.
func (o Opened) LogValue() slog.Value {
	return slog.GroupValue(slog.String("plaintext", "REDACTED"), slog.Bool("stale", o.Stale))
}

// Seal seals pt for r under the KEK's current key.
func Seal(ctx context.Context, k kek.KEK, r Ref, pt []byte) ([]byte, error) {
	aad := r.AAD()
	if aad == nil {
		return nil, ErrInvalidRef
	}
	ct, err := k.Seal(ctx, pt, aad)
	if err != nil {
		return nil, errors.Join(errors.New("sealing: seal "+r.kind.name()), err)
	}
	return ct, nil
}

// Open opens ct as the secret r names. A ciphertext of another purpose, tenant or row fails.
func Open(ctx context.Context, k kek.KEK, r Ref, ct []byte) (Opened, error) {
	aad := r.AAD()
	if aad == nil {
		return Opened{}, ErrInvalidRef
	}
	pt, err := k.Open(ctx, ct, aad)
	if err != nil {
		return Opened{}, errors.Join(errors.New("sealing: open "+r.kind.name()), err)
	}
	id, err := k.KeyIDOf(ct)
	if err != nil {
		return Opened{}, errors.Join(errors.New("sealing: open "+r.kind.name()), err)
	}
	return Opened{Plaintext: pt, Stale: id != k.CurrentKeyID()}, nil
}

// OpenLegacy opens a v0.16 blob of the secret r names, trying the exact v0.16 associated data in
// order: tenant + ":" + user for a TOTP seed, tenant + ":" + provider for an OAuth client secret,
// the tenant for a signing key, then no associated data. It returns ErrLegacyUnopenable when none
// opens the blob, so the row is reported rather than skipped, and ErrNoLegacyFormat for the data
// key.
func OpenLegacy(ctx context.Context, legacy kek.LegacyOpener, r Ref, blob []byte) ([]byte, error) {
	var first kek.AAD
	switch r.kind {
	case kindTOTP, kindOAuthClientSecret:
		first = kek.AAD(r.tenant.String() + ":" + r.id)
	case kindSigningKey:
		first = kek.AAD(r.tenant.String())
	case kindDataKey:
		return nil, ErrNoLegacyFormat
	default:
		return nil, ErrInvalidRef
	}
	var errs []error
	for _, aad := range []kek.AAD{first, nil} {
		pt, err := legacy.OpenLegacy(ctx, blob, aad)
		if err == nil {
			return pt, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(append([]error{ErrLegacyUnopenable}, errs...)...)
}
