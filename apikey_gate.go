package egauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/tokens"
)

const (
	apiKeySeparator   = "_"
	apiKeySecretBytes = 32
	apiKeyCacheSize   = 4096

	reasonKeyOwner = "owner_unusable"
	reasonKeyGrant = "invalid_grant"
)

type apiKeyGrantWire struct {
	Roles  []string `json:"roles"`
	Scopes []string `json:"scopes"`
	Groups []string `json:"groups"`
}

func newAPIKeySecret(prefix string) (string, []byte, error) {
	b := make([]byte, apiKeySecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	secret := prefix + apiKeySeparator + base64.RawURLEncoding.EncodeToString(b)
	return secret, apiKeyHash(secret), nil
}

func apiKeyHash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func encodeAPIKeyGrant(roles, scopes, groups []string) ([]byte, error) {
	return json.Marshal(apiKeyGrantWire{Roles: nonNil(roles), Scopes: nonNil(scopes), Groups: nonNil(groups)})
}

func decodeAPIKeyGrant(b []byte) (apiKeyGrantWire, error) {
	var g apiKeyGrantWire
	if len(b) == 0 {
		return g, nil
	}
	if err := json.Unmarshal(b, &g); err != nil {
		return apiKeyGrantWire{}, errors.Join(errors.New("egauth: API key grant does not decode"), err)
	}
	return g, nil
}

func intersect(held, granted []string) []string {
	out := []string{}
	for _, v := range granted {
		if slices.Contains(held, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

type apiKeyEntry[C any] struct {
	epoch  uint64
	at     time.Time
	claims AppClaims[C]
}

type apiKeyCache[C any] struct {
	mu      sync.Mutex
	entries map[uuid.UUID]apiKeyEntry[C]
}

func newAPIKeyCache[C any]() *apiKeyCache[C] {
	return &apiKeyCache[C]{entries: map[uuid.UUID]apiKeyEntry[C]{}}
}

func (c *apiKeyCache[C]) get(id uuid.UUID) (apiKeyEntry[C], bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	e.claims = e.claims.clone()
	return e, ok
}

func (c *apiKeyCache[C]) put(id uuid.UUID, e apiKeyEntry[C]) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[id]; !ok && len(c.entries) >= apiKeyCacheSize {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	e.claims = e.claims.clone()
	c.entries[id] = e
}

func (c *apiKeyCache[C]) drop(id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, id)
}

type apiGate[C any] struct {
	a     *Auth[C]
	spec  routes.APISpec
	h     PrincipalHandler[C]
	cache *apiKeyCache[C]
}

type keyRefusal struct {
	status int
	code   string
	reason string
}

func (k keyRefusal) failed() bool { return k.status != 0 }

var (
	keyUnauthenticated = keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated}
	keyUnavailable     = keyRefusal{status: http.StatusServiceUnavailable, code: codeUnavailable}
)

func (g *apiGate[C]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	o := g.a.owned
	tenant, err := o.preamble.Tenant(r)
	if err != nil {
		g.refuse(w, keyUnauthenticated)
		return
	}
	if g.a.sessionCookie(r) {
		g.refuse(w, keyUnauthenticated)
		return
	}
	secret, ok := bearerCredential(r)
	if !ok {
		g.refuse(w, keyUnauthenticated)
		return
	}
	p, ref := g.verify(r.Context(), tenant, secret)
	if ref.failed() {
		if ref.reason != "" {
			_ = audit.Emit(r.Context(), o.events, event.APIKeyAuthFailed, audit.Scope{TenantID: tenant.String()}, audit.Detail{Reason: ref.reason}, nil)
		}
		g.refuse(w, ref)
		return
	}
	info, _ := p.APIKey()
	_ = audit.Emit(r.Context(), o.events, event.APIKeyAuthSucceeded, audit.Scope{TenantID: tenant.String(), UserID: info.Owner.User.String()},
		audit.Detail{}, nil, audit.A(event.KeyKeyType, info.Kind), audit.A(event.KeyKeyID, info.ID.String()))
	g.h(w, withPrincipal(r, p), p)
}

func (g *apiGate[C]) refuse(w http.ResponseWriter, ref keyRefusal) {
	if ref.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	refuse(w, ref.status, ref.code)
}

func (g *apiGate[C]) verify(ctx context.Context, tenant core.TenantID, secret string) (Principal[C], keyRefusal) {
	o := g.a.owned
	hash := apiKeyHash(secret)
	k, err := g.a.cfg.Storage.Tokens.GetAPIKey(ctx, tenant, hash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Principal[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: event.ReasonAPIKeyNotFound}
	case err != nil:
		return Principal[C]{}, keyUnavailable
	}
	now := o.clock.Now()
	switch {
	case subtle.ConstantTimeCompare(k.KeyHash, hash) != 1:
		return Principal[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: event.ReasonAPIKeyNotFound}
	case k.Owner.Tenant != tenant:
		return Principal[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: event.ReasonAPIKeyTenantMismatch}
	case !k.RevokedAt.IsZero():
		return Principal[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: event.ReasonAPIKeyRevoked}
	case !k.ExpiresAt.IsZero() && !now.Before(k.ExpiresAt):
		return Principal[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: event.ReasonAPIKeyExpired}
	case !slices.Contains(g.spec.Kinds(), k.Kind):
		return Principal[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: event.ReasonAPIKeyWrongType}
	}
	claims, ref := g.effectiveClaims(ctx, k, now)
	if ref.failed() {
		return Principal[C]{}, ref
	}
	if g.spec.Check(k.Kind, routes.Claims{Roles: claims.Roles, Scopes: claims.Scopes, Groups: claims.Groups}) != nil {
		return Principal[C]{}, keyRefusal{status: http.StatusForbidden, code: codeForbidden}
	}
	grant, _ := decodeAPIKeyGrant(k.AppClaims)
	info := APIKeyInfo{
		ID: k.ID, Kind: k.Kind, Name: k.Name, Owner: k.Owner, Roles: grant.Roles, Scopes: grant.Scopes, Groups: grant.Groups,
		CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt,
	}
	p, err := apiKeyPrincipal(info, claims)
	if err != nil {
		return Principal[C]{}, keyUnauthenticated
	}
	return p, keyRefusal{}
}

func (g *apiGate[C]) effectiveClaims(ctx context.Context, k tokens.APIKey, now time.Time) (AppClaims[C], keyRefusal) {
	o := g.a.owned
	epoch, err := o.epochs.Current(ctx, k.Owner)
	switch {
	case errors.Is(err, store.ErrNotFound):
		g.cache.drop(k.ID)
		return AppClaims[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: reasonKeyOwner}
	case err != nil:
		return AppClaims[C]{}, keyUnavailable
	}
	if e, ok := g.cache.get(k.ID); ok && e.epoch == epoch && now.Sub(e.at) < g.a.cfg.Policy.RecheckEvery && !now.Before(e.at) {
		return e.claims, keyRefusal{}
	}
	g.cache.drop(k.ID)
	state, err := o.identity.AccountState(ctx, k.Owner)
	if err != nil {
		return AppClaims[C]{}, keyUnavailable
	}
	if !state.Exists() || state.Disabled() || state.Deleted() {
		return AppClaims[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: reasonKeyOwner}
	}
	grant, err := decodeAPIKeyGrant(k.AppClaims)
	if err != nil {
		return AppClaims[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: reasonKeyGrant}
	}
	owner, err := g.a.cfg.Claims.ClaimsFor(ctx, k.Owner)
	switch {
	case errors.Is(err, ErrUnknownSubject):
		return AppClaims[C]{}, keyRefusal{status: http.StatusUnauthorized, code: codeUnauthenticated, reason: reasonKeyOwner}
	case err != nil:
		return AppClaims[C]{}, keyUnavailable
	}
	eff := AppClaims[C]{
		Roles: intersect(owner.Roles, grant.Roles), Scopes: intersect(owner.Scopes, grant.Scopes), Groups: intersect(owner.Groups, grant.Groups),
		Custom: owner.Custom,
	}
	if state.Epoch() == epoch {
		g.cache.put(k.ID, apiKeyEntry[C]{epoch: epoch, at: now, claims: eff})
	}
	return eff, keyRefusal{}
}
