package egauth

import (
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/principal"
)

// CredentialKind says what a request authenticated with. It is the PrincipalKind of the design;
// the legacy egauth.PrincipalKind keeps that name until the cutover deletes it.
type CredentialKind uint8

const (
	// Anonymous is a request with no credential, or one that failed a gate of an Optional route.
	Anonymous CredentialKind = iota
	// Session is an established human session that passed every gate of its route.
	Session
	// APIKey is an API key of a kind the route accepts.
	APIKey
)

// Principal is the authenticated entity of a request, passed to handlers as an argument. The zero
// Principal is Anonymous. Values are produced only by the route handlers of Build (and, in tests,
// by egauthtest.NewPrincipal).
type Principal[C any] struct {
	kind    CredentialKind
	subject principal.Subject
	attrs   principal.SessionAttrs
	claims  AppClaims[C]
	apiKey  APIKeyInfo
	caller  principal.Caller
}

// PrincipalHandler serves a declared route with the principal its gates admitted.
type PrincipalHandler[C any] func(w http.ResponseWriter, r *http.Request, p Principal[C])

// APIKeyInfo describes an API key without its secret. Roles, Scopes and Groups are the claims the
// key was granted, a subset of its owner's; ExpiresAt is zero for a key that never expires.
type APIKeyInfo struct {
	ID        uuid.UUID
	Kind      string
	Name      string
	Owner     principal.Subject
	Roles     []string
	Scopes    []string
	Groups    []string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (k APIKeyInfo) clone() APIKeyInfo {
	k.Roles, k.Scopes, k.Groups = slices.Clone(k.Roles), slices.Clone(k.Scopes), slices.Clone(k.Groups)
	return k
}

func (c AppClaims[C]) clone() AppClaims[C] {
	c.Roles, c.Groups, c.Scopes = slices.Clone(c.Roles), slices.Clone(c.Groups), slices.Clone(c.Scopes)
	return c
}

func sessionPrincipal[C any](res session.Resumed, claims AppClaims[C]) (Principal[C], error) {
	caller, err := res.Caller()
	if err != nil {
		return Principal[C]{}, err
	}
	return withCaller(res.Attrs(), claims, caller), nil
}

func resourcePrincipal[C any](a principal.SessionAttrs, claims AppClaims[C]) (Principal[C], error) {
	caller, err := core.ResourceTokenCaller(a)
	if err != nil {
		return Principal[C]{}, err
	}
	return withCaller(a, claims, caller), nil
}

func detachedSessionPrincipal[C any](a principal.SessionAttrs, claims AppClaims[C]) (Principal[C], error) {
	caller, err := core.SessionCaller(a, uuid.New(), nil)
	if err != nil {
		return Principal[C]{}, err
	}
	return withCaller(a, claims, caller), nil
}

func withCaller[C any](a principal.SessionAttrs, claims AppClaims[C], caller principal.Caller) Principal[C] {
	return Principal[C]{kind: Session, subject: a.Subject(), attrs: a, claims: claims.clone(), caller: caller}
}

func apiKeyPrincipal[C any](info APIKeyInfo, claims AppClaims[C]) (Principal[C], error) {
	caller, err := core.APIKeyCaller(info.Owner, info.ID)
	if err != nil {
		return Principal[C]{}, err
	}
	return Principal[C]{kind: APIKey, subject: info.Owner, apiKey: info.clone(), claims: claims.clone(), caller: caller}, nil
}

// Kind returns what the request authenticated with.
func (p Principal[C]) Kind() CredentialKind { return p.kind }

// Subject returns the user, or the owner of the API key; it is zero for Anonymous.
func (p Principal[C]) Subject() principal.Subject { return p.subject }

// Session returns the sealed session attributes, and false unless Kind is Session.
func (p Principal[C]) Session() (principal.SessionAttrs, bool) {
	if p.kind != Session {
		return principal.SessionAttrs{}, false
	}
	return p.attrs, true
}

// SessionID returns the session lineage id, stable across rotation, Reissue and reauthentication,
// and false unless Kind is Session.
func (p Principal[C]) SessionID() (uuid.UUID, bool) {
	if p.kind != Session {
		return uuid.Nil, false
	}
	return p.attrs.Lineage(), true
}

// Claims returns a copy of the application claims; it is zero for Anonymous. For an API key it is
// the owner's current claims intersected with the key's grant.
func (p Principal[C]) Claims() AppClaims[C] { return p.claims.clone() }

// APIKey returns the key, and false unless Kind is APIKey.
func (p Principal[C]) APIKey() (APIKeyInfo, bool) {
	if p.kind != APIKey {
		return APIKeyInfo{}, false
	}
	return p.apiKey.clone(), true
}

// Caller returns the facade caller of this principal; it is the zero Caller, refused by every
// facade, for Anonymous. On a ResourceServer route it is a principal.CallerResourceToken, refused
// by every facade with ErrResourceTokenCaller although Kind is Session. A session Caller is bound
// to the stored session it was resumed from: facades refuse it with ErrSessionEnded once that
// session is logged out, revoked or reissued.
func (p Principal[C]) Caller() principal.Caller { return p.caller }
