# passkey — WebAuthn / passkeys (incl. discoverable login)

import: `github.com/JLugagne/egauth/passkey`
memory stores: `github.com/JLugagne/egauth/passkey/memory`
postgres stores: `github.com/JLugagne/egauth/adapters/pgx/passkey` (credential `Store` + shared `ChallengeStore`)
source: `passkey/*.go`
underlying lib: `github.com/go-webauthn/webauthn`

## Purpose

Registration and login ceremonies over WebAuthn/FIDO2. Supports identified login (userID known before Begin) and discoverable/usernameless login (resident-key; user identity resolved from credential user handle at Finish). Stateless server: challenge + UV requirement carried in an HMAC-SHA256-authenticated secure cookie between Begin and Finish. Replay protection via a mandatory server-side single-use ChallengeStore (SEC-05).

## Service interface

```go
func NewService(store Store, cfg Config) (*Service, error)

// Registration
func (s *Service) BeginRegistration(ctx context.Context, tenantID string, userID uuid.UUID, name, displayName string) (*protocol.CredentialCreation, *webauthn.SessionData, error)
func (s *Service) FinishRegistration(ctx context.Context, tenantID string, userID uuid.UUID, name, displayName string, session webauthn.SessionData, r *http.Request) (*Credential, error)

// Identified login (userID known up front)
func (s *Service) BeginLogin(ctx context.Context, tenantID string, userID uuid.UUID) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
func (s *Service) FinishLogin(ctx context.Context, tenantID string, userID uuid.UUID, session webauthn.SessionData, r *http.Request) (*Credential, error)

// Discoverable / usernameless login (no prior userID)
func (s *Service) BeginDiscoverableLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error)
func (s *Service) FinishDiscoverableLogin(ctx context.Context, tenantID string, session webauthn.SessionData, r *http.Request) (*Credential, uuid.UUID, error)

// Credential management
func (s *Service) ListCredentials(ctx context.Context, tenantID string, userID uuid.UUID) ([]*Credential, error)
func (s *Service) DeleteCredential(ctx context.Context, tenantID string, userID uuid.UUID, credentialID []byte) error
```

## Key types

### Credential

```go
type Credential struct {
    UserID    uuid.UUID
    TenantID  string
    ID        []byte    // raw credential ID; unique per authenticator
    PublicKey []byte
    SignCount uint32
    Data      []byte    // JSON of webauthn.Credential (source of truth for go-webauthn)
    CreatedAt time.Time
}
```

### Config

```go
type Config struct {
    RPID                     string                               // registrable domain, no scheme/port e.g. "example.com"
    RPDisplayName            string                               // shown by authenticator UI
    RPOrigins                []string                             // allowed origins e.g. ["https://example.com"]
    UserVerification         protocol.UserVerificationRequirement // zero value = VerificationRequired (secure default)
    CookieKey                []byte                               // HMAC-SHA256 key, >= 32 bytes; REQUIRED
    ChallengeStore           ChallengeStore                       // single-use replay protection; REQUIRED unless InsecureNoChallengeStore
    InsecureNoChallengeStore bool                                 // opt-out of ChallengeStore requirement (NOT for passwordless)
    Events                   event.Sink                           // optional; receives LoginSucceeded / AccountBlocked events
}
```

### Ceremony session type

`*webauthn.SessionData` from `github.com/go-webauthn/webauthn/webauthn` — carries challenge, expiry, and UV requirement. The handlers serialize it into the HMAC-authenticated cookie; callers using Service directly must carry it themselves between Begin and Finish.

## Constructors

```go
// Multi-tenant
svc, err := passkey.NewService(store, cfg)

// Single-tenant wrapper (uses empty tenant "" for all calls)
st := passkey.NewSingleTenant(svc)
st.Service() // returns underlying *Service when explicit tenant needed

// Memory stores (tests / single-process)
store   := memory.NewStore()
chStore := memory.NewChallengeStore()
```

### SingleTenant method signatures

Identical to Service but without the `tenantID` parameter:

```go
func (s *SingleTenant) BeginRegistration(ctx context.Context, userID uuid.UUID, name, displayName string) (*protocol.CredentialCreation, *webauthn.SessionData, error)
func (s *SingleTenant) FinishRegistration(ctx context.Context, userID uuid.UUID, name, displayName string, session webauthn.SessionData, r *http.Request) (*Credential, error)
func (s *SingleTenant) BeginLogin(ctx context.Context, userID uuid.UUID) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
func (s *SingleTenant) FinishLogin(ctx context.Context, userID uuid.UUID, session webauthn.SessionData, r *http.Request) (*Credential, error)
func (s *SingleTenant) BeginDiscoverableLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error)
func (s *SingleTenant) FinishDiscoverableLogin(ctx context.Context, session webauthn.SessionData, r *http.Request) (*Credential, uuid.UUID, error)
func (s *SingleTenant) ListCredentials(ctx context.Context, userID uuid.UUID) ([]*Credential, error)
func (s *SingleTenant) DeleteCredential(ctx context.Context, userID uuid.UUID, credentialID []byte) error
```

## Stores

```go
// Store persists WebAuthn credentials. All ops are tenant-scoped; "" is the single-tenant partition.
type Store interface {
    SaveCredential(ctx context.Context, tenantID string, c *Credential) error
    GetCredentials(ctx context.Context, tenantID string, userID uuid.UUID) ([]*Credential, error)
    UpdateCredential(ctx context.Context, tenantID string, c *Credential) error
    DeleteCredential(ctx context.Context, tenantID string, userID uuid.UUID, credentialID []byte) error
}

// ChallengeStore provides single-use TTL-bounded challenge storage (replay protection SEC-05).
// Consume MUST be atomic: second call for same (tenantID, challenge) returns (false, nil).
type ChallengeStore interface {
    Put(ctx context.Context, tenantID, challenge string, expiresAt time.Time) error
    Consume(ctx context.Context, tenantID, challenge string) (bool, error)
}
```

`memory.Store` and `memory.ChallengeStore` implement these interfaces; both are safe for concurrent use. `adapters/pgx/passkey` ships `NewStore` and `NewChallengeStore` (plus `DeleteExpired(ctx) (int64, error)` to prune unfinished ceremonies); the shared `passkey/storetest` suite pins both backends to the same contract.

## HTTP handlers

All four handlers accept only `POST`. `UserResolver` is required; nil resolver returns 401.

```go
type UserResolver    func(r *http.Request) (userID uuid.UUID, name, displayName, tenant string, ok bool)
type LoginSuccessFunc func(w http.ResponseWriter, r *http.Request, userID uuid.UUID)
```

| Handler | Resp on success | Body / cookie |
|---|---|---|
| `BeginRegistrationHandler(svc, opts...)` | 200 JSON `*protocol.CredentialCreation` | Sets `__Host-passkey_ceremony` cookie (HMAC-signed SessionData) |
| `FinishRegistrationHandler(svc, opts...)` | 204 | Reads cookie; POST body = attestation response (capped at 64 KiB) |
| `BeginLoginHandler(svc, opts...)` | 200 JSON `*protocol.CredentialAssertion` | Sets `__Host-passkey_ceremony` cookie |
| `FinishLoginHandler(svc, opts...)` | 204 (or LoginSuccessFunc) | Reads cookie; POST body = assertion response (capped at 64 KiB) |

Discoverable login has no dedicated handlers; call `BeginDiscoverableLogin` / `FinishDiscoverableLogin` directly and manage the session cookie manually (or build thin wrappers matching the pattern above).

### Handler options

```go
WithUserResolver(r UserResolver)          // required
WithLoginSuccess(f LoginSuccessFunc)      // called on FinishLogin success; default: 204
WithCookieKey(key []byte)                 // override per-handler (normally set in Config)
WithChallengeStore(cs ChallengeStore)     // override per-handler
WithSessionCookieName(name string)        // default: "__Host-passkey_ceremony"
WithSessionTTL(d time.Duration)           // default: 5 min
WithCookieDomain(domain string)
WithSameSite(mode http.SameSite)          // default: Lax
WithInsecureCookies()                     // clear Secure flag (local HTTP dev only)
WithMaxBodyBytes(n int64)                 // default: 64 KiB; <=0 disables cap
WithTrustedOrigins(origins ...string)     // widen the same-origin CSRF allowlist (hosts, no scheme)
WithInsecureNoOriginCheck()               // turn the CSRF check OFF (opt-out, not the default)
```

Every state-changing passkey handler (including `RenameCredentialHandler` and the discoverable pair)
applies the strict same-origin CSRF check first: a POST whose `Origin` (or `Referer` fallback) host is
neither the request `Host` nor an allowlisted host is refused with 403 `cross_site_blocked`, and a POST
carrying neither header counts as untrusted.

The ceremony cookie name carries the browser-enforced `__Host-` prefix by default. `WithCookieDomain`
and `WithInsecureCookies` are incompatible with it, so they DEMOTE the name (`__Secure-` or bare);
Begin and Finish derive it the same way, so the ceremony never splits across two names.

Body cap constants:
```go
const DefaultMaxBodyBytes int64 = 64 << 10  // 65536 bytes
const DefaultSessionTTL        = 5 * time.Minute
const DefaultSessionCookieName = "__Host-passkey_ceremony"
const MinCookieKeyLength       = 32
```

## Errors

```go
var ErrNilStore             = errors.New("passkey: NewService requires a non-nil Store")
var ErrCookieKeyMissing     = errors.New("passkey: Config.CookieKey is required and must be at least 32 bytes")
var ErrCookieKeyWeak        = errors.New("passkey: Config.CookieKey has no entropy (every byte is identical); generate it with crypto/rand")
var ErrChallengeStoreMissing = errors.New("passkey: a ChallengeStore is required for replay protection; ...")
var ErrNoCredentials        = errors.New("passkey: no credentials registered")
var ErrCredentialNotFound   = errors.New("passkey: credential not found")
var ErrCredentialExists     = errors.New("passkey: credential already exists")
var ErrCredentialCloned     = errors.New("passkey: authenticator signature counter regressed (possible clone)")
var ErrSessionInvalid       = errors.New("passkey: ceremony session is missing or invalid")
var ErrTenantMismatch       = errors.New("passkey: tenant ID mismatch")
```

HTTP error mapping (via `fail`):

| Sentinel | Status |
|---|---|
| `ErrSessionInvalid` | 400 `session_invalid` |
| `ErrNoCredentials` | 400 `no_credentials` |
| `ErrCredentialCloned` | 401 `credential_cloned` |
| `ErrCredentialNotFound` | 404 `credential_not_found` |
| `ErrCredentialExists` | 409 `credential_exists` |
| `*protocol.Error` | 400 `verification_failed` |
| other | 500 `internal_error` |

## Security notes

- **UserVerification**: zero value of `Config.UserVerification` = `protocol.VerificationRequired`. UV-cleared assertions rejected at Finish. Explicitly set `VerificationPreferred`/`VerificationDiscouraged` to relax.
- **Cookie authentication**: ceremony cookie is HMAC-SHA256 signed with `CookieKey` (prepended 32-byte tag + base64url). Tampered or missing cookies → `ErrSessionInvalid`. Cookie is single-use: cleared on every `loadSession` call regardless of outcome.
- **Replay protection**: `ChallengeStore.Consume` called on Finish before assertion verification. Second Consume of same challenge returns false → 400. Atomic Consume is a contract requirement on implementations.
- **Clone detection**: regressed signature counter → `ErrCredentialCloned` + `AccountBlocked` event emitted.
- **Body cap**: Finish handlers wrap `r.Body` in `http.MaxBytesReader` at `DefaultMaxBodyBytes` (64 KiB) to prevent memory-pressure DoS.
- **Origin/RPID checks**: enforced by go-webauthn; RPID and RPOrigins must match the frontend exactly. Independently, the HTTP handlers apply their own same-origin CSRF check (403 `cross_site_blocked`) — see `WithTrustedOrigins`.
- **Cookie key entropy**: `NewService` rejects a length-valid but entropy-free key (all bytes identical, e.g. `make([]byte, 32)`) with `ErrCookieKeyWeak`; the per-handler and per-tenant key paths fail the request closed on the same key.
- **Ceremony timeout**: 5 min, enforced server-side via `Timeouts.Enforce: true` in go-webauthn config.

## Wiring

```go
import (
    "github.com/JLugagne/egauth/passkey"
    "github.com/JLugagne/egauth/passkey/memory"
)

store   := memory.NewStore()
chStore := memory.NewChallengeStore()

svc, err := passkey.NewService(store, passkey.Config{
    RPID:          "example.com",
    RPDisplayName: "Example",
    RPOrigins:     []string{"https://example.com"},
    CookieKey:     cookieSecret, // []byte, >= 32 bytes
    ChallengeStore: chStore,
    // UserVerification defaults to VerificationRequired
})

resolver := func(r *http.Request) (uuid.UUID, string, string, string, bool) {
    // extract authenticated userID + tenant from session/JWT
    return userID, name, displayName, tenant, true
}

mux.Handle("POST /passkey/register/begin",  passkey.BeginRegistrationHandler(svc, passkey.WithUserResolver(resolver)))
mux.Handle("POST /passkey/register/finish", passkey.FinishRegistrationHandler(svc, passkey.WithUserResolver(resolver)))
mux.Handle("POST /passkey/login/begin",     passkey.BeginLoginHandler(svc, passkey.WithUserResolver(resolver)))
mux.Handle("POST /passkey/login/finish",    passkey.FinishLoginHandler(svc,
    passkey.WithUserResolver(resolver),
    passkey.WithLoginSuccess(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
        // Issue the session token yourself. STAMP THE FACTOR: set
        // Claims.AMR = []string{tokens.AMRWebAuthn} (the same "hwk" the audit event records).
        // egauth's factor-mutating and destructive handlers (mfa.DisableHandler,
        // mfa.RegenerateRecoveryCodesHandler, identity.DeleteAccountHandler) require a credential
        // whose AMR carries a step-up factor, and they fail CLOSED — a passkey session with an empty
        // AMR is refused with 403 step_up_required.
    }),
))

// Discoverable login (no userID needed on Begin)
assertion, session, err := svc.BeginDiscoverableLogin()
// store session in cookie manually, then:
cred, userID, err := svc.FinishDiscoverableLogin(ctx, tenant, session, r)
```

## Audit events (M9 uniform login-method audit)

Both login paths emit a `login.succeeded` event with uniform `Attrs`:

| Method | `method` attr | `amr` attr | extra |
|---|---|---|---|
| `FinishLogin` (identified) | `"passkey"` | `["hwk"]` | — |
| `FinishDiscoverableLogin` (usernameless) | `"passkey"` | `["hwk"]` | `Reason="passkey_discoverable"` |

`"hwk"` is the RFC 8176 Authentication Method Reference for a hardware-key / WebAuthn authenticator. The `Reason` field on the discoverable path is kept alongside the uniform `Attrs` so consumers can distinguish the two passkey flows.

The events are emitted on the `Config.Events` sink configured at `NewService`.

## Gotchas

- **Discoverable vs identified login**: `BeginDiscoverableLogin` takes no userID; `allowCredentials` is empty so the authenticator selects the key. `FinishDiscoverableLogin` resolves the user from the credential's user handle (UUID bytes). Multi-tenant: pass `tenantID` derived from request (host/subdomain), not from the credential.
- **Challenge store eviction**: `memory.ChallengeStore` reclaims expired entries with a bounded, amortised prune per `Put` and hard-caps the live set at `memory.DefaultMaxChallengeEntries` (override with `memory.WithMaxEntries`), evicting oldest-first — `Put` is reachable unauthenticated, so it must not grow without bound. It stays PER-PROCESS: a multi-replica deployment must use `pgx.NewChallengeStore` from `adapters/pgx/passkey`, otherwise a ceremony begun on one pod fails on another.
- **RPID/origin must match frontend**: RPID = registrable domain (no scheme, no port). RPOrigins = full origin strings (scheme + host + optional port). Mismatch → go-webauthn `*protocol.Error` → 400.
- **CookieKey rotation**: all in-flight ceremonies using the old key fail at Finish (HMAC mismatch → `ErrSessionInvalid`). Rotate during low-traffic windows; ceremony TTL is 5 min.
- **SingleTenant misuse**: `NewSingleTenant` hard-wires tenant `""`. Do NOT mix `SingleTenant` calls with multi-tenant `Service` calls against the same store; `""` is a real partition key that could collide with an explicit tenant.
- **InsecureNoChallengeStore**: disables `ErrChallengeStoreMissing` enforcement. Without a `ChallengeStore`, a captured Finish request (cookie + body) can be replayed within the 5-min cookie TTL. Do not use for passwordless or step-up flows.
