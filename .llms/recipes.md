# recipes — common wiring stacks

Copy-pasteable composition patterns. Signatures verified against source. `ctx := context.Background()`,
`const tenant = ""` (single-tenant default partition) unless multi-tenant. Swap any `*/memory` store for
its `adapters/pgx/*` counterpart in production (see [storage-pgx.md](storage-pgx.md)).

---

## 1. Password login + stateless JWT (the canonical stack)

`identity` verifies credentials; `tokens/basic` issues the access+refresh pair. Most apps carry no
custom claims → use `basic` (no `[struct{}]` type argument). For custom claims use generic `tokens`/`tokens/jwt`.

```go
import (
    egauth "github.com/JLugagne/egauth"
    "github.com/JLugagne/egauth/identity"
    identitymem "github.com/JLugagne/egauth/identity/memory"
    "github.com/JLugagne/egauth/passwords/argon2"
    "github.com/JLugagne/egauth/passwords/policy"
    "github.com/JLugagne/egauth/tokens/basic"
)

idStore := identitymem.NewStore()
svc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy())

// claimsProvider re-derives claims on every refresh → disabled/role-changed users re-evaluated, not frozen.
claims := basic.ClaimsProviderFunc(func(_ context.Context, uid uuid.UUID, tid string) (basic.Claims, error) {
    return basic.Claims{Subject: uid, TenantID: tid}, nil
})
issuer := basic.NewIssuer(basic.Config{
    Store:          basic.NewMemoryStore(),
    Issuer:         "example-app",
    SecretKey:      secret,          // >= 32 bytes, from your secret store
    AccessTTL:      15 * time.Minute,
    RefreshTTL:     720 * time.Hour,
    ClaimsProvider: claims,          // REQUIRED for Rotate
})

// programmatic
user, _ := svc.Register(ctx, tenant, "alice@example.com", password)
pair, _ := issuer.IssueTokenPair(ctx, basic.Claims{Subject: user.ID, TenantID: tenant})
next, _ := issuer.Rotate(ctx, tenant, pair.RefreshToken) // single-use; replay trips theft detection

// HTTP
claimsOf := func(u *identity.User) basic.Claims { return basic.Claims{Subject: u.ID, TenantID: u.TenantID} }
mux := http.NewServeMux()
mux.Handle("POST /login",   identity.LoginHandler(svc, issuer, claimsOf))
mux.Handle("POST /refresh", basic.RefreshHandler(issuer))
mux.Handle("POST /logout",  basic.LogoutHandler(basic.NewMemoryStore())) // revokes refresh family
mux.Handle("GET /me", basic.RequireAuth(issuer,
    func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, _ struct{}) {
        // actor.UserID / actor.TenantID authenticated
    }))
```

Details: [identity.md](identity.md), [tokens.md](tokens.md), [passwords.md](passwords.md).

---

## 2. Password login + server-side sessions (revocable)

Use `sessions` instead of `tokens` when you need server-side revocation, idle timeout, and fixation
defense. `identity` still verifies credentials.

```go
import (
    "github.com/JLugagne/egauth/sessions"
    sessmem "github.com/JLugagne/egauth/sessions/memory"
)

sessSvc := sessions.NewService(sessmem.NewStore(), sessions.WithMaxLifetime(720*time.Hour))

user, _ := svc.Authenticate(ctx, tenant, "password", "alice@example.com", password)
sess, token, _ := sessSvc.CreateSession(ctx, tenant, user.ID, r.UserAgent(), clientIP, 24*time.Hour)
// set `token` in a cookie yourself, or use the middleware:

mux.Handle("GET /me", sessions.RequireSession(sessSvc,
    func(w http.ResponseWriter, r *http.Request, s *sessions.Session) { /* s.UserID authenticated */ }))

// idle-extend on activity: sessSvc.Touch(ctx, tenant, token, 24*time.Hour)
// after privilege change (login): rotate the id to defeat fixation:
newSess, newToken, _ := sessSvc.Rotate(ctx, tenant, token, 24*time.Hour)
```

Details: [sessions.md](sessions.md). MUST schedule `DeleteExpired` eviction (recipe 8).

---

## 3. Social login (OAuth2 / OIDC) + JIT identity linking

`oauth` runs the authorization-code + PKCE flow and verifies the id_token; the callback links/creates
an `identity.User` and issues tokens. Provider constructors live in `oauth/providers`.

```go
import (
    "github.com/JLugagne/egauth/oauth"
    "github.com/JLugagne/egauth/oauth/providers"
)

google := providers.Google(clientID, clientSecret, oauth.WithOIDC(oauth.OIDCConfig{Audience: clientID}))

mux.Handle("GET /auth/google",          oauth.BeginHandler(google, oauth.WithRedirectURL("https://app.example.com/auth/google/callback")))
mux.Handle("GET /auth/google/callback", oauth.CallbackHandler(google, svc /* identity.Service is the IdentityLinker */, issuer, claimsOf,
    oauth.WithRedirectURL("https://app.example.com/auth/google/callback")))
// Begin mints state(CSRF)+PKCE(+nonce), redirects to provider. Callback validates state, exchanges code,
// verifies UserInfo/id_token, JIT-links identity, sets auth cookies → 204.

// Multi-tenant SSO (per-tenant providers): use a ProviderStore + Dynamic*Handler
store := oauth.NewMemoryStore()
store.AddProvider("tenant-a", providers.Okta(/* ... */))
mux.Handle("GET /sso/begin",    oauth.DynamicBeginHandler(store, "okta", oauth.WithTenantResolver(tenantFromHost)))
mux.Handle("GET /sso/callback", oauth.DynamicCallbackHandler(store, "okta", svc, issuer, claimsOf, oauth.WithTenantResolver(tenantFromHost)))
```

12 providers: Apple, Auth0, Cognito, Discord, Facebook, GitHub, GitLab(+SelfHosted), Google, Keycloak,
LinkedIn, Microsoft, Okta, plus generic `providers.New(...)` for any OIDC issuer. Details: [oauth.md](oauth.md).

---

## 4. Add TOTP MFA (second factor) + step-up

`mfa` = TOTP (RFC 6238) + recovery codes. SMS is intentionally NOT an MFA factor. After verifying the
second factor, mint tokens whose `AMR` includes `mfa` and gate sensitive routes with `Claims.FreshAuth`.

```go
import (
    "github.com/JLugagne/egauth/mfa"
    mfamem "github.com/JLugagne/egauth/mfa/memory"
)

mfaSvc := mfa.NewService(mfamem.NewStore(), mfa.WithIssuer("Example"))
resolve := func(r *http.Request) (uuid.UUID, string, bool) { return userID, tenant, true } // from session/JWT

mux.Handle("POST /mfa/enroll",  mfa.EnrollHandler(mfaSvc, mfa.WithUserResolver(resolve)))  // → {secret, otpauth:// uri}
mux.Handle("POST /mfa/confirm", mfa.ConfirmHandler(mfaSvc, mfa.WithUserResolver(resolve))) // → {recovery_codes:[...]}
mux.Handle("POST /mfa/verify",  mfa.VerifyHandler(mfaSvc, mfa.WithUserResolver(resolve)))  // 204 / 429 too_many_attempts

// step-up: issue access token with AMR after factor verified; protect route with FreshAuth:
if !claims.FreshAuth(5 * time.Minute) { http.Error(w, "reauth_required", 401); return }
```

Details: [mfa.md](mfa.md), `AuthTime`/`AMR`/`FreshAuth` in [tokens.md](tokens.md).

---

## 5. Passwordless: passkeys (WebAuthn)

`passkey` runs WebAuthn register/login ceremonies, including discoverable (usernameless) login. RPID/origins
MUST match the frontend. Pairs with tokens/sessions on the finish step.

```go
import (
    "github.com/JLugagne/egauth/passkey"
    pkmem "github.com/JLugagne/egauth/passkey/memory"
)

svc, _ := passkey.NewService(pkmem.NewStore(), passkey.Config{
    RPID: "example.com", RPDisplayName: "Example", RPOrigins: []string{"https://example.com"},
    CookieKey: cookieSecret /* >=32B */, ChallengeStore: pkmem.NewChallengeStore(),
})
mux.Handle("POST /passkey/register/begin",  passkey.BeginRegistrationHandler(svc, passkey.WithUserResolver(resolver)))
mux.Handle("POST /passkey/register/finish", passkey.FinishRegistrationHandler(svc, passkey.WithUserResolver(resolver)))
mux.Handle("POST /passkey/login/begin",     passkey.BeginLoginHandler(svc, passkey.WithUserResolver(resolver)))
mux.Handle("POST /passkey/login/finish",    passkey.FinishLoginHandler(svc, passkey.WithUserResolver(resolver),
    passkey.WithLoginSuccess(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID) { /* issue token */ })))
```

Details: [passkey.md](passkey.md).

---

## 6. Passwordless: email/SMS one-time codes

`otp` issues short-lived single-use codes; you own delivery. Handlers are enumeration-safe (Issue always 204;
Verify collapses all failures to 401).

```go
import (
    "github.com/JLugagne/egauth/otp"
    otpmem "github.com/JLugagne/egauth/otp/memory"
)

otpSvc := otp.NewService(otpmem.NewStore(), otp.WithTTL(10*time.Minute))
deliver := func(ctx context.Context, ch *otp.Challenge) error { return sendEmail(ch /* ch.Code */) }

mux.Handle("POST /otp/issue",  otp.IssueHandler(otpSvc, deliver, otp.WithSubjectResolver(subjFromReq)))
mux.Handle("POST /otp/verify", otp.VerifyHandler(otpSvc, otp.WithSubjectResolver(subjFromReq),
    otp.WithOnVerified(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID) { /* issue token/session */ })))
```

Details: [otp.md](otp.md). MUST schedule `DeleteExpired` eviction (recipe 8).

---

## 7. Password reset / email verification / magic link

All `Request*` handlers are enumeration-safe (always 204) and dispatch delivery asynchronously off the
response path. Wire your transport into `identity.Mailer` / `identity.SMSSender` (egauth never sends mail/SMS).

```go
mailer := identity.Mailer{
    PasswordReset:     func(ctx context.Context, m identity.PasswordResetMail) error { return send(m.User.Email, resetURL(m.Token)) },
    EmailVerification: func(ctx context.Context, m identity.EmailVerificationMail) error { return send(m.User.Email, verifyURL(m.Token)) },
    MagicLink:         func(ctx context.Context, m identity.MagicLinkMail) error { return send(m.User.Email, magicURL(m.Token)) },
}
mux.Handle("POST /password-reset/request", identity.RequestPasswordResetHandler(svc, mailer))
mux.Handle("POST /password-reset/confirm", identity.ResetPasswordHandler(svc))
mux.Handle("POST /verify-email/request",   identity.RequestEmailVerificationHandler(svc, mailer, identity.WithUserResolver(userFromReq)))
mux.Handle("POST /verify-email/confirm",   identity.VerifyEmailHandler(svc))
mux.Handle("POST /magic-link/request",     identity.RequestMagicLinkHandler(svc, mailer))
mux.Handle("POST /magic-link/login",       identity.MagicLinkLoginHandler(svc, issuer, claimsOf))
```

Tokens passed to delivery callbacks are plaintext secrets — never log them. Details: [identity.md](identity.md).

---

## 8. Production hardening: pgx stores + eviction + events + rate limit + breach check

```go
import (
    identitypgx "github.com/JLugagne/egauth/adapters/pgx/identity"
    "github.com/JLugagne/egauth/event"
    "github.com/JLugagne/egauth/janitor"
    "github.com/JLugagne/egauth/passwords/breach/hibp"
    "github.com/JLugagne/egauth/ratelimit"
)

// 1. pgx stores (separate module `go get github.com/JLugagne/egauth/adapters/pgx`)
pool, _ := pgxpool.New(ctx, dsn)
_ = identitypgx.Migrate(ctx, pool)           // once at startup; forward-only, idempotent
idStore := identitypgx.NewStore(pool)

// 2. security events → slog
sink := event.NewSlogSink(slog.Default())
svc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy(), identity.WithEventSink(sink))

// 3. breach check (HIBP k-anonymity) — pass to policy/registration per passwords.md
breach := hibp.New()

// 4. rate-limit login (token bucket) — see infra.md for middleware signature
limiter := ratelimit.NewTokenBucket(/* burst */ 5, /* refillInterval */ time.Minute)

// 5. eviction loop — REQUIRED for in-memory stores (sessions/otp) + TokenBucket, else unbounded growth.
//    pgx stores evict via DB; skip for those.
j := janitor.Start(ctx, 5*time.Minute, func() {
    sessStore.DeleteExpired(context.Background(), tenant)
    otpStore.DeleteExpired(context.Background(), tenant)
    limiter.Cleanup()
})
defer j.Stop()
```

Details: [storage-pgx.md](storage-pgx.md), [infra.md](infra.md), [passwords.md](passwords.md).

---

## 9. API keys

`tokens` issues long-lived API keys alongside JWTs; only a SHA-256 hash is stored.

```go
apiKey, _ := issuer.IssueAPIKey(ctx, "sk_live", basic.Claims{Subject: user.ID, TenantID: tenant})
// apiKey.Key is shown ONCE to the user; verify later:
claims, err := verifier.VerifyAPIKey(ctx, tenant, presentedKey)
```

Details: [tokens.md](tokens.md).

---

## Single-tenant shorthand (any module)

```go
app := identity.NewSingleTenant(svc) // drops the tenantID arg from every call (uses "")
user, _ := app.Register(ctx, "bob@example.com", password)
```
Available on identity, sessions, mfa, otp, passkey, tokens/jwt.
