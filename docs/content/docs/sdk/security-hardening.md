---
title: "Security Hardening"
weight: 9
---

# Security Hardening

`egauth` ships secure-by-default primitives, but several controls are **opt-in** because they
encode a policy decision (a cost ceiling, an absolute timeout, a rate limit) that only you can
make for your deployment. This page is the single checklist of those settings: what to set, the
middleware to wire, and why each one matters.

Everything here reflects the current code. Where a control is OFF by default, that is called out
explicitly so you can decide deliberately rather than inherit a silent default.

> [!WARNING]
> **Read this before going to production.** Some controls are fail-closed defaults (passkey user
> verification and challenge binding, credential-enrolment gates, the session absolute-lifetime
> cap), but the policy decisions still need you: key material must come from a secret manager,
> OIDC fetches must keep the SSRF guard, and unauthenticated endpoints must be rate-limited
> against mail/SMS bombing.

## Quick checklist

| Area | Control | Default | Action |
|------|---------|---------|--------|
| Passwords | Argon2 cost + rehash-on-login | safe defaults, no auto-rehash | Tune cost; call `NeedsRehash` after login |
| Tokens (JWT) | `iss` / `aud` validation | `iss` checked if set; `aud` **off** | Set `Issuer` + `ExpectedAudience` |
| Tokens (JWT) | Access-token tenant binding | fail-closed when `MultiTenant` set | Set `MultiTenant: true`; call `VerifyAccessTokenForTenant` |
| Sessions | Cookie name (`__Host-` prefix) | **secure by default** (`__Host-session_token`) | Leave it; `WithCookieName` only as an escape hatch |
| Sessions | Absolute lifetime | **on** (30-day cap) | Tune with `WithMaxLifetime`; `WithNoMaxLifetime` opts out (insecure) |
| Sessions | Log-out-everywhere | available | Call `RevokeAllForUser` on reset/compromise |
| Passkeys | User Verification | **required** (zero value = `VerificationRequired`) | Relax to `VerificationPreferred`/`Discouraged` only when another factor already authenticated the user |
| Passkeys | Replay protection | **on** (`ChallengeStore` + `CookieKey` required, fail-fast) | `Config.InsecureNoChallengeStore` knowingly accepts cookie-only protection; **do not** use for passwordless |
| Passkeys | Credential-enrollment gate | **fail-closed** (`403 assurance_required` unless wired) | Wire `WithCredentialAssurance(tokens.DenyInterim)`; `WithInsecureNoAssuranceCheck` is the loud opt-out |
| Passkeys | Account eraser | **must be registered** (`passkeySvc.AccountEraser()` via `identity.WithAccountErasers`) | None; without it an attacker-enrolled passkey survives a password reset |
| MFA | Enrolment gate | **fail-closed** (`403 assurance_required` unless wired) | Wire `mfa.WithCredentialAssurance(tokens.DenyInterim)`; `WithInsecureNoAssuranceCheck` opts out |
| MFA | Step-up issuance state | **fail-closed** (`500 misconfigured` without a resolver) | Wire `mfa.WithSessionStateResolver(idSvc.(issuance.Resolver))` (the concrete identity service implements it); `WithInsecureEchoSessionState` restores legacy echo |
| OAuth/OIDC | State-cookie signing key | **required** (`WithStateSigningKey`, >= 32 bytes, 500 otherwise) | None; key comes from your secret manager |
| OAuth/OIDC | HTTPS on provider URLs | **enforced** (deferred error fails the begin path closed) | Leave on; never `WithInsecureURLs` in prod |
| OAuth/OIDC | JWKS bound to issuer (discovery) | enforced | Provide only the `Issuer` on the dynamic store |
| OAuth/OIDC | Issuer allowlist (BYO-SSO) | **off** | `WithIssuerAllowlist` for untrusted tenants |
| OAuth/OIDC | SSRF-safe HTTP client | **on** (token, userinfo, discovery, JWKS) | Leave it on; opt out only for a controlled internal/dev IdP |
| HTTP | Rate limiting on `Request*` | **off** | Wrap with the `ratelimit` middleware |
| HTTP | `webapp.NewWebApp` auth endpoints | **on** (per-IP `TokenBucket` on login/register/refresh/logout; event sink defaults to slog) | Tune `RateLimitBurst`/`RateLimitRefill` or replace with `RateLimiter`; `InsecureNoRateLimit` to opt out |

---

## Passwords (Argon2id)

### Cost parameters

`NewHasher()` uses safe defaults (`m=65536, t=1, p=4`, 32-byte key, 16-byte salt). Tune them to
your hardware's latency budget with functional options — the zero-argument call is unchanged, so
raising the cost is a deliberate opt-in:

```go
import "github.com/JLugagne/egauth/passwords/argon2"

hasher := argon2.NewHasher(
	argon2.WithMemory(128*1024), // KiB
	argon2.WithTime(3),
	argon2.WithThreads(4),
)
```

`Compare` is hardened against corrupt/foreign stored hashes: malformed PHC parameters (e.g.
`t=0`, `p=0`, an empty digest, or a memory below Argon2's per-thread floor) are rejected as an
ordinary mismatch instead of panicking the process.

### Rehash on login

A weak **imported** hash (migrated from another system, or hashed under a now-raised default)
would otherwise verify cheaply forever. After a *successful* `Compare`, ask whether the stored
hash is below your current target and, if so, transparently upgrade it:

```go
if err := hasher.Compare(ctx, storedHash, plaintext); err != nil {
	// authentication failed
	return
}

// Rehash-on-login: NeedsRehash is a concrete method on *argon2.Hasher.
if hasher.NeedsRehash(storedHash) {
	if newHash, err := hasher.Hash(ctx, plaintext); err == nil {
		_ = identityStore.UpdatePasswordHash(ctx, tenantID, userID, newHash) // your store
	}
}
```

`NeedsRehash` returns `true` when any stored cost parameter is below the hasher's target, or when
the hash is malformed / a foreign format — so legacy formats get upgraded to canonical Argon2id on
the next login. It performs no key derivation and never mutates state.

---

## Tokens (JWT)

A JWT verifier that checks neither `iss` nor `aud` is a confused-deputy risk when one symmetric
(HS256) key is shared across services: a token minted for one service is accepted by another. Set
both:

```go
import jwtissuer "github.com/JLugagne/egauth/tokens/jwt"

svc := jwtissuer.New(jwtissuer.Config[MyClaims]{
	Store:            tokenStore,
	Issuer:           "https://auth.example.com",      // stamped AND verified
	ExpectedAudience: []string{"api.example.com"},     // any-of; verified on the access path
	SecretKey:        secret,
	AccessTTL:        15 * time.Minute,
	// ...
})
```

- **`Issuer`** — when set, it is both stamped at issuance and **verified** on
  `VerifyAccessToken`. Leaving it empty disables the `iss` check (backward compatible).
- **`ExpectedAudience`** — any-of semantics: a token is accepted only if its `aud` contains at
  least one configured value. Empty disables the `aud` check. **Set it whenever a signing key is
  shared across more than one audience/service.**

### Tenant binding on the access path (fail-closed when multi-tenant)

When one `Service` signs for every tenant under a shared key, a token minted for tenant A is
cryptographically valid in tenant B's context. The tenant-unaware `VerifyAccessToken` does **no**
tenant comparison and is **deprecated**. Multi-tenant deployments must declare themselves so the
unsafe path fails closed:

```go
svc := jwtissuer.New(jwtissuer.Config[MyClaims]{
	Store:       tokenStore,
	Issuer:      "https://auth.example.com",
	SecretKey:   secret,
	AccessTTL:   15 * time.Minute,
	MultiTenant: true, // VerifyAccessToken now returns ErrTenantBindingRequired
	// ...
})

// Always bind the token to the request's resolved tenant:
claims, err := svc.VerifyAccessTokenForTenant(ctx, requestTenantID, token)
```

- With `MultiTenant: true`, the deprecated `VerifyAccessToken` returns
  `tokens.ErrTenantBindingRequired` instead of silently verifying cross-tenant — use
  `VerifyAccessTokenForTenant`, which rejects a mismatch with `tokens.ErrTenantMismatch`.
- Genuinely single-tenant apps leave `MultiTenant` false (every token is issued under the empty
  tenant) and may keep calling `VerifyAccessToken`, or use the `SingleTenant` wrapper.

Prefer the **rotation keyset** (`SigningKeys` + `ActiveKeyID`) over a single `SecretKey` so you
can roll keys with overlapping validity, and wire an `EventSink` to capture refresh-token
reuse / family-revocation events for auditing.

---

## Sessions

### Hardened cookie name (secure by default)

`sessions.RequireSession` reads the session token from `sessions.DefaultSessionCookieName`
(`"__Host-session_token"`) by default. The browser-enforced `__Host-` prefix host-locks the
cookie — it must be `Secure`, carry no `Domain`, and use `Path=/` — which defeats
subdomain/sibling-host cookie-tossing session fixation. This is the default; you no longer opt in.

```go
// Secure by default — no option needed:
mux.Handle("/app", sessions.RequireSession(sessionSvc, handler))

// Escape hatch ONLY when the deployment genuinely cannot use a __Host- cookie
// (e.g. a path-scoped cookie, or local plain-HTTP development):
mux.Handle("/app", sessions.RequireSession(sessionSvc, handler,
	sessions.WithCookieName("session_token")))
```

Overriding to a name without the `__Host-` prefix forfeits the host-lock hardening; that is a
deliberate consumer choice. Whatever name you read with must match the name your login handler
writes the session cookie with.

### Absolute lifetime (off by default)

Idle timeout alone lets a kept-warm stolen token live forever. Cap the total lifetime measured
from creation — `Touch`/`Rotate` will clamp the sliding expiry to this deadline and
`ValidateSession` rejects past it:

```go
import "github.com/JLugagne/egauth/sessions"

sessionSvc := sessions.NewService(
	sessionStore,
	sessions.WithMaxLifetime(12*time.Hour), // shorten the 30-day default cap
)
```

### Log out everywhere

After a password reset, an MFA change, or a suspected compromise, kill every other session for
the user — not just the current token:

```go
// Multi-tenant service:
err := sessionSvc.RevokeAllForUser(ctx, tenantID, userID)

// Single-tenant wrapper:
err := singleTenant.RevokeAllForUser(ctx, userID)
```

Always pair this with a fresh login + `Rotate` for the legitimate user, and emit your own audit
event.

---

## Passkeys (WebAuthn)

### User Verification is required by default

The zero value of `Config.UserVerification` is `protocol.VerificationRequired`: an assertion whose
User Verified (UV) flag is unset is rejected at Finish across registration, login and discoverable
login. Leave it at the default for passwordless/step-up; relax it explicitly to
`VerificationPreferred` / `VerificationDiscouraged` **only** for a flow where another factor
already authenticated the user.

```go
import (
	"github.com/JLugagne/egauth/passkey"
	"github.com/go-webauthn/webauthn/protocol"
)

svc, err := passkey.NewService(store, passkey.Config{
	RPID:             "example.com",
	RPDisplayName:    "Example Inc",
	RPOrigins:        []string{"https://example.com"},
	UserVerification: protocol.VerificationRequired, // explicit; also the zero-value default
})
```

### Ceremony key and replay protection are required (fail-fast)

`Config.CookieKey` (at least `passkey.MinCookieKeyLength` = 32 bytes; screened by the shared
credential policy against all-zero/repeated-byte, published-example and near-copy values) and a
`Config.ChallengeStore` are required: `NewService` returns `ErrCookieKeyMissing` /
`ErrChallengeStoreMissing` at construction, so a misconfiguration fails at startup instead of
degrading silently. The challenge is recorded on Begin and atomically consumed on Finish, so a
captured Finish request cannot be replayed within the cookie TTL.

```go
import (
	"github.com/JLugagne/egauth/passkey"
	passkeymem "github.com/JLugagne/egauth/passkey/memory"
)

svc, err := passkey.NewService(store, passkey.Config{
	RPID:           "example.com",
	RPDisplayName:  "Example Inc",
	RPOrigins:      []string{"https://example.com"},
	CookieKey:      cookieKey,                      // >= 32 bytes, from a secret manager
	ChallengeStore: passkeymem.NewChallengeStore(), // process-local; back with a shared store in a cluster
})
```

> [!NOTE]
> `Config.InsecureNoChallengeStore` knowingly accepts cookie-only protection (no server-side
> replay binding); **do not** use it for passwordless. In a load-balanced deployment, back
> `passkey.ChallengeStore` with a shared store (e.g. Redis) so Begin and Finish can land on
> different replicas; the in-memory store is per-process.

### Registration is gated fail-closed

`BeginRegistrationHandler` / `FinishRegistrationHandler` answer `403 assurance_required` unless an
assurance gate is wired. Wire `passkey.WithCredentialAssurance(tokens.DenyInterim)` — it refuses an
interim (pre-second-factor) session, so a password-only attacker cannot enrol an authenticator;
token-less (session-based) applications and fully-elevated sessions pass.
`passkey.WithInsecureNoAssuranceCheck()` is the loud opt-out. The gate runs before the ceremony
cookie is read or the challenge consumed.

### Register the account eraser

`passkey.Service.AccountEraser()` deletes every passkey a user has registered. Register it with
`identity.WithAccountErasers` alongside `tokens.NewAccountRevoker(...)` so a password reset,
password change or account deletion evicts passkeys — without it, a passkey an attacker enrolled
while holding the password survives the victim's remediation and keeps minting sessions.

---

## OAuth 2.0 / OIDC

### HTTPS is enforced (keep it that way)

Provider auth/token URLs and — for OIDC — the issuer/JWKS/discovery URLs must be `https`. An
`http://` token endpoint would leak `client_secret`; an `http://` JWKS allows MITM key
substitution. The only escape hatch is the loud, dev-only `WithInsecureURLs()` (and the matching
`OIDCConfig.AllowInsecureURLs`):

```go
// LOCAL DEV ONLY — never in production:
p := oauth.New(name, id, secret, authURL, tokenURL, scopes, fetch, oauth.WithInsecureURLs())
```

### JWKS is bound to the issuer via discovery

For OIDC providers, `egauth` derives the authoritative `jwks_uri` from the issuer's
`/.well-known/openid-configuration`, verifies the discovery document's `issuer` matches, and binds
the JWKS host to the issuer host. A tenant therefore **cannot** pair a trusted issuer string with
attacker-controlled keys. On the dynamic (database-backed) store, supply **only the `Issuer`** and
let discovery resolve the keys; a hand-supplied `JWKSURL` is accepted only as a same-host override.

### Bring-your-own-SSO: SSRF defence and an issuer allowlist

If you let untrusted tenants register their own OIDC providers, every server-side fetch must go
through the SSRF-hardened client, whose dialer rejects loopback, link-local/cloud-metadata, and
private/RFC1918 addresses **at dial time** (defeating DNS rebinding):

```go
import "github.com/JLugagne/egauth/oauth"

client := oauth.SafeHTTPClient() // use for any tenant-supplied URL
```

The dynamic `pgx` store already validates registered URLs (`https`, non-internal) and uses
`SafeHTTPClient()` automatically. For an extra policy layer, constrain registration/resolution to a
vetted set of issuers — OFF by default so single-operator setups are unaffected:

```go
import oauthpgx "github.com/JLugagne/egauth/adapters/pgx/oauth"

store := oauthpgx.NewStore(pool,
	oauthpgx.WithIssuerAllowlist([]string{
		"https://accounts.google.com",
		"https://login.microsoftonline.com/common/v2.0",
	}),
)
```

### State-cookie signing key is required

The CSRF state cookie also carries the PKCE code verifier and OIDC nonce, so it is
HMAC-SHA-256 authenticated with `oauth.WithStateSigningKey` — a stable random secret of at least
`oauth.MinStateSigningKeyLength` (32) bytes from your secret manager. Every mounted auth handler
needs it; a missing, short, trivially-known, published-example or near-copy key fails closed with
`500` at request time (and validate at startup with `oauth.ValidateHandlerConfig`). The cookie is
`HttpOnly` + `Secure` + `SameSite=Lax` and host-locked by the `__Host-oauth_state` default name.

```go
stateKey := stateSigningKeyFromSecretStore // >= 32 bytes, unique per deployment

beginOpts := []oauth.HandlerOption{
	oauth.WithRedirectURL("https://yourapp.com/auth/google/callback"),
	oauth.WithStateSigningKey(stateKey),
}
callbackOpts := append(beginOpts, oauth.WithSuccessRedirect("/dashboard"))
```

### State cookie is bound to provider + tenant

The OAuth state cookie carries the provider name and tenant, and the callback rejects a state
minted for a different provider/tenant (`provider_mismatch` / `tenant_mismatch`). This closes
provider- and tenant-confusion when several providers or tenants share one host — no configuration
required; it is automatic in `BeginHandler`/`CallbackHandler` and the dynamic variants.

### JWKS parsing is bounded

A hostile issuer's JWKS is capped at 16 keys, and RSA keys are bounded to `[2048, 8192]`-bit moduli
with a sane exponent range, limiting CPU/memory amplification on a cache-miss. No action needed —
documented here so you know the limits.

---

## Rate limiting the `Request*` endpoints

> [!CAUTION]
> **This is off by default and you must wire it.** The unauthenticated `RequestPasswordReset` and
> `RequestMagicLink` handlers take a *victim's* email; `RequestPhoneVerification` takes an
> attacker-chosen number into a **paid SMS sender**. Left unthrottled they enable mail-bombing,
> link spam, and — most costly — **SMS toll-fraud** (pumping verification texts to premium-rate or
> attacker-controlled numbers to burn your SMS budget).

`egauth` does not throttle these for you (rate, key, and backing store are deployment policy), but
the `ratelimit` package is the ready seam. (The `webapp` preset is the exception: it throttles the
login/register/refresh/logout routes it mounts per client IP by default — see
[SECURITY.md](https://github.com/JLugagne/egauth/blob/main/SECURITY.md) and the `webapp.Config`
rate-limit fields.) Apply defence in depth:

**1. Per client IP** — the cheap blanket cap on every `Request*` endpoint:

```go
import "github.com/JLugagne/egauth/ratelimit"

limiter := ratelimit.NewTokenBucket(5, time.Minute) // burst 5, then 1/min per key
resetHandler := ratelimit.Wrap(
	limiter,
	ratelimit.ClientIP, // RemoteAddr-based; supply a proxy-aware KeyFunc behind a trusted LB
	identity.RequestPasswordResetHandler(svc, mailer),
)
```

**2. Per account / per destination** — so one victim email can't be bombed from many IPs, and one
user can't fan out to many numbers. The key reads the request form, so it is application-specific:

```go
perEmail := func(r *http.Request) string {
	return "email:" + strings.ToLower(r.FormValue("email"))
}
throttled := ratelimit.Wrap(ratelimit.NewTokenBucket(3, 5*time.Minute), perEmail, resetHandler)
```

For phone verification, **key on the destination number** and additionally cap your SMS provider's
spend and allowlist the dialing regions you serve:

```go
perNumber := func(r *http.Request) string { return "phone:" + r.FormValue("phone") }
phone := ratelimit.Wrap(ratelimit.NewTokenBucket(2, 10*time.Minute), perNumber,
	identity.RequestPhoneVerificationHandler(svc, sender))
```

See the runnable examples on the `ratelimit` package (godoc / pkg.go.dev) for the per-IP,
per-account, per-destination, and layered recipes. The reference `TokenBucket` is process-local;
back the `ratelimit.Limiter` interface with a shared store (e.g. Redis) for a multi-instance
deployment.

---

## Production checklist (TL;DR)

- [ ] Argon2 cost tuned to your latency budget; `NeedsRehash` called after every successful login.
- [ ] JWT `Issuer` set and `ExpectedAudience` set wherever a key is shared across services.
- [ ] Prefer JWT `SigningKeys` rotation over a single `SecretKey`; wire an `EventSink`.
- [ ] Review `sessions.WithMaxLifetime` around the 30-day default; `RevokeAllForUser` called on reset/compromise.
- [ ] Passkey `CookieKey` + `ChallengeStore` supplied at construction; registration gate wired; `passkeySvc.AccountEraser()` registered with `identity.WithAccountErasers`.
- [ ] MFA `EnrollHandler`/`ConfirmHandler` gate wired; `StepUpHandler` given `WithSessionStateResolver`.
- [ ] OAuth handlers given a random `WithStateSigningKey` (>= 32 bytes) from a secret manager.
- [ ] No `WithInsecureURLs` / `AllowInsecureURLs` anywhere in production config.
- [ ] BYO-SSO: `SafeHTTPClient()` for tenant URLs; `WithIssuerAllowlist` set; only `Issuer` supplied to the dynamic store (discovery resolves JWKS).
- [ ] All `Request*` endpoints wrapped with `ratelimit` (per-IP **and** per-account/destination); SMS provider spend cap + region allowlist in place.
- [ ] Session/auth cookies are `HttpOnly`, `Secure`, `SameSite=Lax` (or stricter).
