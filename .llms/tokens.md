# tokens — stateless JWT access + refresh rotation + API keys

import (generic core): `github.com/JLugagne/egauth/tokens`
import (jwt impl):     `github.com/JLugagne/egauth/tokens/jwt`
import (basic facade, no custom claims): `github.com/JLugagne/egauth/tokens/basic`
import (memory store): `github.com/JLugagne/egauth/tokens/memory`
source: `tokens/*.go`, `tokens/jwt/*.go`, `tokens/basic/*.go`, `tokens/memory/*.go`

## Purpose

All core types are generic over `C` — the application's custom claims payload embedded in `Claims[C]`. Set `C = struct{}` when no custom claims are needed; use the `basic` package for a zero-type-argument facade that specializes everything to `C = struct{}` automatically. The JWT reference implementation (`tokens/jwt`) signs access tokens with a pluggable scheme — symmetric HS256 by default, or asymmetric RS256/ES256/ES384/ES512/EdDSA via the `Signer` abstraction (see `jwt.Signer`) — plus opaque random refresh tokens; the generic interfaces (`Issuer[C]`, `Rotator[C]`, `Verifier[C]`, `Store[C]`) allow alternate backends.

## Core interfaces (tokens)

```go
type Issuer[C any] interface {
    IssueTokenPair(ctx context.Context, claims Claims[C]) (*TokenPair[C], error)
    IssueAPIKey(ctx context.Context, prefix string, claims Claims[C]) (*APIKey[C], error)
}

type Verifier[C any] interface {
    // DEPRECATED, no tenant binding. With jwt.Config.MultiTenant=true it fails closed
    // (ErrTenantBindingRequired); use VerifyAccessTokenForTenant instead.
    VerifyAccessToken(ctx context.Context, token string) (*Claims[C], error)
    // Tenant-bound access-token verification; rejects ErrTenantMismatch unless the signed
    // tenant_id == tenantID. tenantID="" for single-tenant. RequireAuth uses this when a
    // tenant resolver is configured (WithAuthTenantResolver).
    VerifyAccessTokenForTenant(ctx context.Context, tenantID string, token string) (*Claims[C], error)
    // tenantID="" for single-tenant
    VerifyRefreshToken(ctx context.Context, tenantID string, token string) (*Claims[C], error)
    VerifyAPIKey(ctx context.Context, tenantID string, key string) (*Claims[C], error)
}

type Rotator[C any] interface {
    // Consumes refreshToken, issues fresh pair in same family.
    // ErrRefreshTokenReused on replay → revokes whole family.
    Rotate(ctx context.Context, tenantID string, refreshToken string) (*TokenPair[C], error)
}

type ClaimsProvider[C any] interface {
    // Called during Rotate to resolve fresh claims; error aborts rotation (old token is NOT consumed to allow retry on transient error).
    ClaimsForUser(ctx context.Context, userID uuid.UUID, tenantID string) (Claims[C], error)
}

type Store[C any] interface {
    SaveRefreshToken(ctx context.Context, tenantID string, rt *RefreshToken) error
    FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*RefreshToken, error)
    // Returns ErrRefreshTokenNotFound or ErrRefreshTokenReused on replay.
    ConsumeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error
    RevokeRefreshToken(ctx context.Context, tenantID string, tokenHash string) error
    RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error
    SaveAPIKey(ctx context.Context, tenantID string, key *APIKey[C]) error
    FindAPIKeyByHash(ctx context.Context, tenantID string, tokenHash string) (*APIKey[C], error)
    // GC reaper: purge expired rows (consumed tokens kept until expiry for replay detection).
    DeleteExpired(ctx context.Context, tenantID string) (int64, error)
}

type FamilyRevoker interface {
    FindRefreshToken(ctx context.Context, tenantID string, tokenHash string) (*RefreshToken, error)
    RevokeFamily(ctx context.Context, tenantID string, familyID uuid.UUID) error
}
// tokens.Store[C] satisfies FamilyRevoker for any C.
```

## Key types

### `Claims[C any]`
```go
type Claims[C any] struct {
    Subject   uuid.UUID
    TenantID  string
    IssuedAt  time.Time
    // AuthTime: when subject last authenticated (OIDC auth_time). NOT reset by silent refresh.
    // Anchors step-up freshness. Defaults to IssuedAt at issuance; preserved across rotation.
    AuthTime  time.Time
    ExpiresAt time.Time
    Audiences []string
    Scopes    []string
    Groups    []string
    Roles     []string
    // AMR: RFC 8176 authentication method refs (pwd, otp, hwk, mfa).
    // Re-evaluated by ClaimsProvider on every rotation, not frozen at login.
    AMR    []string
    // MustChangePassword is a first-class advisory flag set for admin-provisioned temporary
    // credentials (identity.AdminCreateUser / SetTemporaryPassword). It is a soft gate: a flagged
    // token still authenticates, but RequireAuth with WithPasswordChangeGate soft-redirects to the
    // reset page. The flag is recorded on the refresh-token family and Rotate replays it onto every
    // silent refresh, so a flagged (renewable) session stays gated — a user cannot escape by waiting
    // for the access token to expire. JWT claim name: "must_change_password" (omitempty). Lives
    // here, not in Custom, so the middleware can enforce it generically regardless of C.
    MustChangePassword bool
    Custom             C
}

func (c Claims[C]) FreshAuth(maxAge time.Duration) bool
// Returns true if time.Since(AuthTime) <= maxAge. maxAge<=0 always true; zero AuthTime fails closed.
```

`basic.Claims` = `tokens.Claims[struct{}]`

### `TokenPair[C any]`
```go
type TokenPair[C any] struct {
    AccessToken           string
    RefreshToken          string
    RefreshTokenHash      string    // SHA-256 hex of RefreshToken (for storage)
    AccessTokenExpiresAt  time.Time
    RefreshTokenExpiresAt time.Time
    Claims                Claims[C]
}
// String/GoString/LogValue redact both tokens.
```

### `RefreshToken`
```go
type RefreshToken struct {
    Hash       string     // SHA-256 hex; only this is stored
    FamilyID   uuid.UUID
    UserID     uuid.UUID
    TenantID   string
    AuthTime   time.Time  // preserved across family rotation for step-up anchoring
    ExpiresAt  time.Time
    CreatedAt  time.Time
    ConsumedAt *time.Time // non-nil = consumed (single-use enforced)
}
```

### `APIKey[C any]`
```go
type APIKey[C any] struct {
    ID        uuid.UUID
    TenantID  string
    Prefix    string     // e.g. "sk_live_"
    Token     string     // clear-text, only at creation
    Hash      string     // SHA-256 hex stored in DB
    ExpiresAt *time.Time // nil = never expires
    Claims    Claims[C]
}
// String/GoString/LogValue redact Token.
```

### `jwt.Config[C any]`
```go
type Config[C any] struct {
    Store            tokens.Store[C]
    Issuer           string          // JWT "iss" claim; required
    ExpectedAudience []string        // "aud" gate on verify; empty = disabled
    SecretKey        string          // HS256 single-key mode; >= 32 bytes (MinSecretKeyLength)
    SigningKeys       []SigningKey    // HMAC rotation keyset; when set, SecretKey is verify-only
    // Signers: pluggable signer set (symmetric or asymmetric). When non-empty it supersedes
    // SecretKey/SigningKeys for signing — ActiveKeyID signs, every signer verifies. A non-empty
    // SecretKey alongside Signers is kept as a kid-less legacy verify-only HMAC key. MUST NOT be
    // combined with SigningKeys. Build entries with NewHMACSigner/NewRSASigner/NewECDSASigner/
    // NewEdDSASigner (or implement Signer yourself).
    Signers          []Signer
    ActiveKeyID      string          // selects the active (signing) key among SigningKeys or Signers
    ClaimsProvider   tokens.ClaimsProvider[C] // required for Rotate
    AccessTTL        time.Duration   // required, positive
    RefreshTTL       time.Duration   // required, positive
    RefreshLength    int             // byte length of opaque refresh token (default used if 0)
    APIKeyLength     int             // byte length of API key (default used if 0)
    // ReuseGracePeriod: replay within window = benign concurrency (no family revoke).
    // 0 = DefaultReuseGracePeriod (10s). Negative = strict (any replay revokes family).
    ReuseGracePeriod time.Duration
    EventSink        event.Sink      // optional; receives reuse/revocation security events
    Clock            func() time.Time // override for deterministic tests; zero = time.Now
}

func (cfg Config[C]) Validate() error  // checks key size, non-empty Issuer, positive TTLs
```

`basic.Config` = `jwt.Config[struct{}]`

### `jwt.SigningKey`
```go
type SigningKey struct {
    KeyID  string // emitted as JWT "kid" header
    Secret string // HS256 key material
}
// String/GoString/LogValue redact Secret.
// HMAC-only convenience keyset (Config.SigningKeys). For asymmetric keys use Config.Signers.
```

### `jwt.Signer` — pluggable signing scheme (symmetric or asymmetric)
```go
type Signer interface {
    KeyID() string                  // "kid" header; empty only for the legacy kid-less HMAC signer
    Method() jwt.SigningMethod      // pins the alg; verify rejects any token whose alg differs
    SignKey() any                   // []byte (HMAC) | *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
    VerifyKey() any                 // []byte (HMAC) | crypto.PublicKey
}

// Built-in constructors (all validate and return an error). Pass the result(s) via Config.Signers.
func NewHMACSigner(keyID string, secret []byte) (Signer, error)        // HS256; secret >= 32 bytes; empty keyID allowed
func NewRSASigner(keyID string, key *rsa.PrivateKey) (Signer, error)   // RS256; key >= 2048 bits; keyID required
func NewECDSASigner(keyID string, key *ecdsa.PrivateKey) (Signer, error) // ES256/ES384/ES512 chosen from the curve (P-256/384/521); keyID required
func NewEdDSASigner(keyID string, key ed25519.PrivateKey) (Signer, error) // EdDSA; keyID required
```
The verify path resolves the signer by the token's `kid` (or the legacy signer when absent) and then pins the algorithm: a token is rejected unless `token.alg == signer.Method().Alg()`. This per-kid pin is the alg-confusion / downgrade defense for both symmetric and asymmetric keys (e.g. an `RS256` token presenting a `kid` that maps to an HMAC signer, or `alg=none`, is rejected).

### `jwt.JWK` / `jwt.JWKSet` + `PublicJWKS`
```go
type JWK struct {
    Kty, Use, Alg, Kid string  // "RSA"|"EC"|"OKP"|"oct"; "sig"; RS256/ES256/.../EdDSA/HS256; key id
    N, E               string  // RSA public params (base64url)
    Crv, X, Y          string  // EC (crv/x/y) or OKP (crv "Ed25519"/x); EC y only
}
type JWKSet struct { Keys []JWK `json:"keys"` }

// PublicJWKS returns the static-path verification keys as an RFC 7517 JWK Set for publishing at
// /.well-known/jwks.json. Asymmetric keys publish their full PUBLIC parameters; HMAC keys publish
// metadata only (kty "oct", kid/alg/use) and NEVER the symmetric secret ("k").
func (s *Service[C]) PublicJWKS() JWKSet
```

### `Cookies`
```go
type Cookies struct {
    AccessName  string        // default: "access_token"
    RefreshName string        // default: "refresh_token"
    Domain      string        // empty = host-only
    Path        string        // access cookie path, default "/"
    RefreshPath string        // refresh cookie path, default "/" (keep "/" for auto-refresh middleware)
    SameSite    http.SameSite // default: http.SameSiteLaxMode
    Insecure    bool          // disables Secure attribute; false (secure) by default
}
// Always HttpOnly; Secure is on unless Insecure=true.
```

## Constructors

### jwt package
```go
func New[C any](cfg Config[C]) *Service[C]
// Panics if no coherent signer can be built. Call cfg.Validate() first for comprehensive checks.

func NewSingleTenant[C any](svc *Service[C]) *SingleTenant[C]
// Wraps Service; Rotate drops tenantID, hard-wired to "". ONLY for single-tenant deployments.
```

### basic package (no custom claims, C=struct{})
```go
func NewIssuer(cfg Config) *Issuer              // wraps jwt.New[struct{}]
func NewMemoryStore() Store                     // wraps memory.NewStore[struct{}]
// type ClaimsProviderFunc = tokens.ClaimsProviderFunc[struct{}]
```

### memory package
```go
func NewStore[C any]() *Store[C]
```

### Cookie helpers
```go
func DefaultCookies() Cookies
// Returns: AccessName="access_token", RefreshName="refresh_token", Path="/", RefreshPath="/", SameSite=Lax, Secure=true
```

## Token operations

```go
// Issue a new access+refresh pair (starts a fresh rotation family).
(*jwt.Service[C]).IssueTokenPair(ctx context.Context, claims Claims[C]) (*TokenPair[C], error)

// Issue a long-lived API key with the given prefix and claims.
(*jwt.Service[C]).IssueAPIKey(ctx context.Context, prefix string, claims Claims[C]) (*APIKey[C], error)

// Rotate refresh token: consume old, issue new pair in same family.
// Replay (already-consumed token) → revokes whole family + ErrRefreshTokenReused.
(*jwt.Service[C]).Rotate(ctx context.Context, tenantID string, refreshToken string) (*TokenPair[C], error)
// SingleTenant variant drops tenantID:
(*jwt.SingleTenant[C]).Rotate(ctx context.Context, refreshToken string) (*TokenPair[C], error)

// DEPRECATED: validate JWT access token (per-kid alg-pinned, exp/nbf/iss/aud checked) WITHOUT
// tenant binding. With Config.MultiTenant=true it fails closed (ErrTenantBindingRequired).
// Single-tenant only.
(*jwt.Service[C]).VerifyAccessToken(ctx context.Context, token string) (*Claims[C], error)

// Validate JWT access token AND bind it to tenantID (signed tenant_id claim must equal tenantID,
// else ErrTenantMismatch). Use this in multi-tenant deployments under a shared signing key.
(*jwt.Service[C]).VerifyAccessTokenForTenant(ctx context.Context, tenantID string, token string) (*Claims[C], error)

// Validate opaque refresh token against store (tenant-scoped).
(*jwt.Service[C]).VerifyRefreshToken(ctx context.Context, tenantID string, token string) (*Claims[C], error)

// Validate API key against store (tenant-scoped).
(*jwt.Service[C]).VerifyAPIKey(ctx context.Context, tenantID string, key string) (*Claims[C], error)

// Hash any token/key to SHA-256 hex (for store lookups or manual comparisons).
func HashToken(token string) string

// GC: purge expired refresh tokens and API keys for a tenant. Run hourly per tenant.
Store[C].DeleteExpired(ctx context.Context, tenantID string) (int64, error)
```

## HTTP handlers + middleware

### `RefreshHandler[C]`
- **POST** (any path you mount it on)
- Reads refresh token from refresh cookie; rotates via `Rotator[C].Rotate`; rewrites both cookies.
- On replay: family revoked, cookies cleared, `401 token_reuse_detected`.
- On missing token: `401 missing_refresh_token`.
- On success: `204 No Content` (or `303` if `WithSuccessRedirect` set).

```go
func RefreshHandler[C any](rotator Rotator[C], opts ...HandlerOption) http.HandlerFunc
// basic shorthand (C=struct{}):
func basic.RefreshHandler(rotator tokens.Rotator[struct{}], opts ...tokens.HandlerOption) http.HandlerFunc
```

### `LogoutHandler`
- **POST** (any path)
- Reads refresh token from cookie; revokes whole rotation family via `FamilyRevoker`; always clears cookies.
- Idempotent: `204` even if token absent or already revoked.

```go
func LogoutHandler(revoker FamilyRevoker, opts ...HandlerOption) http.HandlerFunc
// basic re-export:
func basic.LogoutHandler(revoker tokens.FamilyRevoker, opts ...tokens.HandlerOption) http.HandlerFunc
```

### `RequireAuth[C]` middleware
- Reads Bearer token from `Authorization` header by default.
- On success: calls `next(w, r, egauth.Actor{UserID, TenantID}, customClaims C)`.
- On failure: `401 unauthorized`.
- Step-up gates: `403 step_up_required` (AMR or auth age not satisfied).
- Tenant-aware when `WithAuthTenantResolver` is set: resolves the request tenant and verifies via `VerifyAccessTokenForTenant` (fail-closed). A resolver returning `""` → `401` (never falls back to the tenant-unaware path); a token whose `tenant_id` mismatches → `401`. With no resolver the middleware stays single-tenant (verifies via `VerifyAccessToken`), so single-tenant callers are unchanged.

```go
func RequireAuth[C any](verifier Verifier[C], next AuthenticatedHandlerFunc[C], opts ...AuthOption[C]) http.HandlerFunc
type AuthenticatedHandlerFunc[C any] func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, customClaims C)
// basic shorthand:
func basic.RequireAuth(verifier tokens.Verifier[struct{}], next AuthenticatedHandlerFunc, opts ...tokens.AuthOption[struct{}]) http.HandlerFunc
type basic.AuthenticatedHandlerFunc = tokens.AuthenticatedHandlerFunc[struct{}]
```

**`egauth.Actor` injected on success:**
```go
type egauth.Actor struct {
    UserID   uuid.UUID
    TenantID string
}
```

### `AuthOption[C]` — middleware options
| Option | Effect |
|--------|--------|
| `WithCookieAuth[C](Cookies)` | Also read access token from cookie |
| `WithoutHeaderAuth[C]()` | Disable Authorization header read |
| `WithAutoRefresh[C](rotator, cookies)` | Transparent rotation on expired/missing access token (implies cookie read) |
| `WithPersistentAutoRefresh[C]()` | Auto-refresh writes persistent (Max-Age) refresh cookie |
| `WithAuthTenantResolver[C](func(*http.Request) string)` | Tenant-aware mode: resolve tenantID per request; verify via `VerifyAccessTokenForTenant` and scope auto-refresh. `""` return → 401 (fail-closed) |
| `WithRefreshTenantResolver[C](func(*http.Request) string)` | DEPRECATED alias of `WithAuthTenantResolver` |
| `WithRequiredAMR[C](values ...string)` | Require all AMR values present in token (RFC 8176 step-up) |
| `WithMaxAuthAge[C](d time.Duration)` | Require `AuthTime` within d (sudo-mode gate; not reset by silent refresh) |
| `WithPasswordChangeGate[C](resetURL string)` | Soft forced-password-change gate: after successful token verification, if `Claims.MustChangePassword` is true, the wrapped handler is NOT invoked and the request is redirected `303` to `resetURL` (or returns `403 password_change_required` if `resetURL` is empty). The change-password and logout routes should be excluded from this middleware. |

### `HandlerOption` — handler options
| Option | Effect |
|--------|--------|
| `WithCookies(Cookies)` | Replace cookie config wholesale |
| `WithCookieDomain(string)` | Set cookie Domain |
| `WithCookiePath(string)` | Set Path on both cookies |
| `WithRefreshCookiePath(string)` | Set Path on refresh cookie only |
| `WithSameSite(http.SameSite)` | Override SameSite |
| `WithInsecureCookies()` | Disable Secure (dev only) |
| `WithTenantResolver(func(*http.Request) string)` | Resolve tenantID for multi-tenant |
| `WithTrustedOrigins(hosts ...string)` | Enable CSRF origin check (hosts without scheme) |
| `WithSuccessRedirect(url)` | 303 on success instead of 204 |
| `WithFailureRedirect(url)` | 303 to url?error=<code> on failure |
| `WithPersistentRefresh()` | Re-issue persistent refresh cookie |

### Cookie helpers (on `Cookies`)
```go
func (c Cookies) SetAccess(w http.ResponseWriter, accessToken string)
func (c Cookies) SetRefresh(w http.ResponseWriter, refreshToken string, expiresAt time.Time, persistent bool)
func (c Cookies) Access(r *http.Request) (string, bool)
func (c Cookies) Refresh(r *http.Request) (string, bool)
func (c Cookies) Clear(w http.ResponseWriter)      // both cookies
func (c Cookies) ClearAccess(w http.ResponseWriter)
func (c Cookies) ClearRefresh(w http.ResponseWriter)
```

### AMR constants
```go
const (
    AMRPassword = "pwd" // password/passphrase verified
    AMROTP      = "otp" // TOTP authenticator
    AMRWebAuthn = "hwk" // WebAuthn/passkey
    AMRMFA      = "mfa" // multiple factors
)
```

## Errors (sentinels)

```go
var ErrInvalidToken          = errors.New("tokens: invalid token")
var ErrTokenExpired          = errors.New("tokens: token expired")
var ErrInvalidClaims         = errors.New("tokens: invalid claims")
var ErrAPIKeyNotFound        = errors.New("tokens: api key not found")
var ErrRefreshTokenNotFound  = errors.New("tokens: refresh token not found")
var ErrRefreshTokenReused    = errors.New("tokens: refresh token reused")   // triggers family revoke
var ErrNoClaimsProvider      = errors.New("tokens: no claims provider configured for rotation")
var ErrTenantMismatch        = errors.New("tokens: tenant ID mismatch")
```

## Security notes

- **Per-kid alg-pinning**: the access-token verifier resolves the signer by `kid` then pins its algorithm — a token is rejected unless `token.alg == signer.Method().Alg()`. This rejects `alg=none` and alg-confusion/downgrade (e.g. an `RS256`-keyed `kid` presented as `HS256`) for both symmetric (HS256) and asymmetric (RS256/ES256/ES384/ES512/EdDSA) signing.
- **Publishable JWKS**: `Service.PublicJWKS()` returns an RFC 7517 key set. Asymmetric public keys are safe to serve at `/.well-known/jwks.json`; HMAC keys are emitted metadata-only (`kty:"oct"`) and the secret (`k`) is NEVER published.
- **SHA-256 at rest**: refresh tokens and API keys stored as `HashToken(raw)` (SHA-256 hex); clear-text never persisted.
- **Rotation theft detection**: consuming an already-consumed refresh token (`ErrRefreshTokenReused`) immediately revokes the entire rotation family. Replay within `ReuseGracePeriod` (default 10 s) treated as benign concurrency (rejected, family not revoked).
- **Secret redaction**: `TokenPair`, `APIKey`, `jwt.Config`, `jwt.SigningKey`, `jwt.Service` implement `String()`, `GoString()`, `LogValue()` to redact secrets in all fmt/slog paths.
- **Step-up / sudo mode**: `WithRequiredAMR` enforces RFC 8176 AMR; `WithMaxAuthAge` enforces `AuthTime` freshness. `AuthTime` is NOT reset by silent refresh — only a real re-authentication resets it.
- **Key rotation**: `SigningKeys` (HMAC) or `Signers` (any scheme) + `ActiveKeyID` support kid-tagged overlapping-validity key rollover — every key verifies, `ActiveKeyID` signs — so an HMAC→asymmetric migration is just adding the new `Signer` and switching `ActiveKeyID`. Legacy `SecretKey` verifies un-kidded tokens during migration.
- **CSRF**: `WithTrustedOrigins` checks `Origin`/`Referer` host on `RefreshHandler`/`LogoutHandler` POSTs. Without it, CSRF protection is the consumer's responsibility.
- **Cookie security**: always `HttpOnly`; `Secure` is opt-out (`Insecure bool`, defaults false = secure); `SameSite=Lax` by default.
- **Forced-password-change gate** (`WithPasswordChangeGate`): after successful token verification,
  if `Claims.MustChangePassword` is `true`, the wrapped handler is bypassed and the request is
  soft-redirected to the configured reset URL (or `403 password_change_required` if no URL).
  The credential is never invalidated — login always succeeds — only the post-login app surface is
  gated until the user completes the change. A flagged login issues a full, renewable pair; the flag
  is recorded on the refresh-token family and `Rotate` replays it onto every silent refresh
  (overriding the `ClaimsProvider`), so the renewed token is flagged iff the family was — a silent
  refresh cannot drop the flag and bypass the gate. The flag clears only on a fresh login after the
  password changes; to force a change on live sessions, an admin revokes the user's families.
  `tokens.MustChangeResolverFromContext` adapts the verified claims for `mfa.WithMustChangeResolver`,
  preserving the flag through the MFA step-up flow.

## Wiring

```go
import (
    "github.com/JLugagne/egauth/tokens/basic"
    "github.com/JLugagne/egauth/tokens"
)

// 1. Build issuer (panics on bad config; call cfg.Validate() at startup for full check).
issuer := basic.NewIssuer(basic.Config{
    Store:      basic.NewMemoryStore(), // swap for tokens/pgx.NewStore(pool) in production
    Issuer:     "my-app",
    SecretKey:  os.Getenv("TOKEN_SECRET"), // >= 32 bytes
    AccessTTL:  15 * time.Minute,
    RefreshTTL: 720 * time.Hour,
    ClaimsProvider: basic.ClaimsProviderFunc(func(ctx context.Context, userID uuid.UUID, tenantID string) (basic.Claims, error) {
        // fetch user from DB, return claims or error to abort rotation
        return basic.Claims{Subject: userID, TenantID: tenantID}, nil
    }),
})

// 2. Issue pair at login (store RefreshToken, set cookies).
pair, err := issuer.IssueTokenPair(ctx, basic.Claims{Subject: userID})
cookies := tokens.DefaultCookies()
cookies.SetAccess(w, pair.AccessToken)
cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, rememberMe)

// 3. Refresh endpoint.
mux.Handle("POST /auth/refresh", basic.RefreshHandler(issuer,
    tokens.WithCookies(cookies),
    tokens.WithTrustedOrigins("app.example.com"),
))

// 4. Logout endpoint.
mux.Handle("POST /auth/logout", basic.LogoutHandler(issuer.Store /* or the store directly */,
    tokens.WithCookies(cookies),
))

// 5. Protected routes.
mux.Handle("/api/profile", basic.RequireAuth(issuer,
    func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, _ struct{}) {
        // actor.UserID, actor.TenantID available here
    },
    tokens.WithCookieAuth[struct{}](cookies),
))

// 5b. Sensitive route with step-up gate.
mux.Handle("/api/delete-account", basic.RequireAuth(issuer,
    deleteAccountHandler,
    tokens.WithCookieAuth[struct{}](cookies),
    tokens.WithMaxAuthAge[struct{}](5*time.Minute),
))
```

## Gotchas

- `ClaimsProvider` is **required** for `Rotate`; omitting it returns `ErrNoClaimsProvider`. `IssueTokenPair`/`IssueAPIKey` do not need it.
- `SecretKey` must be >= `jwt.MinSecretKeyLength` (32 bytes); `Config.Validate()` enforces this — `New`/`NewIssuer` panics only on structurally broken config, not on short keys.
- Asymmetric signing: set `Config.Signers` with `NewRSASigner`/`NewECDSASigner`/`NewEdDSASigner` (and `ActiveKeyID` when >1). `Signers` supersedes `SecretKey`/`SigningKeys` for signing and MUST NOT be combined with `SigningKeys` (Validate/New reject it). Verifiers fetch the public keys via `Service.PublicJWKS()`. The `basic` facade is HS256-only — use generic `jwt.New[C]` for asymmetric.
- `basic` vs generic: use `basic` when `C = struct{}`; use `jwt.New[C]` / `tokens.RequireAuth[C]` directly when embedding app-specific data in tokens.
- `Store` is **monolithic** in v0.x (no capability split before v1); external implementations must run `tokens/storetest` conformance suite on each upgrade.
- `RefreshPath` on `Cookies` must remain `"/"` when using `WithAutoRefresh` middleware (the browser only sends the refresh cookie on matching paths).
- Single-tenant shortcut: `jwt.NewSingleTenant(svc)` hard-wires `tenantID=""` on `Rotate`; do NOT mix with multi-tenant calls against the same `Service`.
- Consumed refresh rows are retained until `ExpiresAt` for replay detection; run `Store.DeleteExpired` periodically (e.g. hourly) to prevent unbounded growth.
- `WithAutoRefresh`: on expired access token + valid refresh cookie the middleware rotates transparently and proceeds — no redirect. On rotation failure it clears cookies and returns `401`.
