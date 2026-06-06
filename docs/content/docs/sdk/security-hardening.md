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
> **Read this before going to production.** Skipping the opt-in controls below leaves real gaps:
> sessions that never absolutely expire, passkeys that don't enforce user verification, OIDC
> fetches that can be pointed at internal services, and unauthenticated endpoints that can be used
> for mail/SMS bombing.

## Quick checklist

| Area | Control | Default | Action |
|------|---------|---------|--------|
| Passwords | Argon2 cost + rehash-on-login | safe defaults, no auto-rehash | Tune cost; call `NeedsRehash` after login |
| Tokens (JWT) | `iss` / `aud` validation | `iss` checked if set; `aud` **off** | Set `Issuer` + `ExpectedAudience` |
| Sessions | Absolute lifetime | **off** (idle only) | `WithMaxLifetime` |
| Sessions | Log-out-everywhere | available | Call `RevokeAllForUser` on reset/compromise |
| Passkeys | User Verification | **preferred** (not enforced) | `UserVerification: protocol.VerificationRequired` |
| Passkeys | Replay protection | **off** | `WithChallengeStore` + key required |
| OAuth/OIDC | HTTPS on provider URLs | **enforced** | Leave on; never `WithInsecureURLs` in prod |
| OAuth/OIDC | JWKS bound to issuer (discovery) | enforced | Provide only the `Issuer` on the dynamic store |
| OAuth/OIDC | Issuer allowlist (BYO-SSO) | **off** | `WithIssuerAllowlist` for untrusted tenants |
| OAuth/OIDC | SSRF-safe HTTP client | on for the dynamic store | Use `SafeHTTPClient()` for any tenant-supplied URL |
| HTTP | Rate limiting on `Request*` | **off** | Wrap with the `ratelimit` middleware |

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

Prefer the **rotation keyset** (`SigningKeys` + `ActiveKeyID`) over a single `SecretKey` so you
can roll keys with overlapping validity, and wire an `EventSink` to capture refresh-token
reuse / family-revocation events for auditing.

---

## Sessions

### Absolute lifetime (off by default)

Idle timeout alone lets a kept-warm stolen token live forever. Cap the total lifetime measured
from creation — `Touch`/`Rotate` will clamp the sliding expiry to this deadline and
`ValidateSession` rejects past it:

```go
import "github.com/JLugagne/egauth/sessions"

sessionSvc := sessions.NewService(
	sessionStore,
	sessions.WithMaxLifetime(12*time.Hour), // absolute cap; zero = idle timeout only
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

### Enforce User Verification

By default the UV (User Verified) flag is *preferred* but not enforced, which defeats
passwordless and step-up use cases. Require it in the service config — it is propagated into the
ceremony options and the session, so go-webauthn enforces the bit at every Finish:

```go
import (
	"github.com/JLugagne/egauth/passkey"
	"github.com/go-webauthn/webauthn/protocol"
)

svc, err := passkey.NewService(store, passkey.Config{
	RPID:             "example.com",
	RPDisplayName:    "Example Inc",
	RPOrigins:        []string{"https://example.com"},
	UserVerification: protocol.VerificationRequired, // enforce UV (passwordless / step-up)
})
```

### Replay protection (off by default)

The ceremony challenge lives in a signed cookie. Without a server-side single-use consume, a
captured `Finish` request can be replayed within the cookie TTL — and the clone counter is a no-op
for sign-count-0 platform passkeys. Wire a `ChallengeStore` (and the required cookie key) so each
challenge is consumed exactly once:

```go
import (
	"github.com/JLugagne/egauth/passkey"
	passkeymem "github.com/JLugagne/egauth/passkey/memory"
)

challenges := passkeymem.NewChallengeStore() // process-local; back with a shared store in a cluster

beginLogin := passkey.BeginLoginHandler(svc,
	passkey.WithCookieKey(cookieKey),
	passkey.WithChallengeStore(challenges),
)
finishLogin := passkey.FinishLoginHandler(svc,
	passkey.WithCookieKey(cookieKey),
	passkey.WithChallengeStore(challenges), // SAME store on Begin and Finish
)
```

> [!NOTE]
> Pass the **same** `ChallengeStore` to the matching Begin and Finish handlers (registration and
> login). The in-memory store is per-process; for a load-balanced deployment, back the
> `passkey.ChallengeStore` interface with a shared store (e.g. Redis).

`WithCookieKey` is mandatory for the handlers regardless — without it the ceremony cookie is
forgeable and the handlers fail closed (`500 server_misconfigured`).

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
the `ratelimit` package is the ready seam. Apply defence in depth:

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
- [ ] `sessions.WithMaxLifetime` set; `RevokeAllForUser` called on reset/compromise.
- [ ] Passkey `UserVerification: protocol.VerificationRequired`; `WithChallengeStore` + `WithCookieKey` wired on all ceremony handlers.
- [ ] No `WithInsecureURLs` / `AllowInsecureURLs` anywhere in production config.
- [ ] BYO-SSO: `SafeHTTPClient()` for tenant URLs; `WithIssuerAllowlist` set; only `Issuer` supplied to the dynamic store (discovery resolves JWKS).
- [ ] All `Request*` endpoints wrapped with `ratelimit` (per-IP **and** per-account/destination); SMS provider spend cap + region allowlist in place.
- [ ] Session/auth cookies are `HttpOnly`, `Secure`, `SameSite=Lax` (or stricter).
