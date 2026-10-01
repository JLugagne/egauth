# secure-defaults matrix — handler families & outbound HTTP

Derived from the current source. Every exported HTTP handler constructor — and every
`func(http.Handler) http.Handler` middleware constructor — in these packages is
enumerated mechanically by the guard in `internal/securitydefaults` (registry + go/parser
scan):
`authflow`, `identity`, `mfa`, `oauth`, `otp`, `passkey`, `sessions`, `tokens`,
`tokens/basic`, `webapp`. A constructor in any other package is covered by review only;
this matrix records the control each family applies *by default* and the option that opts out or
widens it. For a control the library can judge on its own — an origin check, a body cap, a cookie
attribute, a signature — the safe value is the zero/absent value and nothing is opt-in. The one
exception is a **product policy** the library cannot judge for you: whether an account must present a
second factor. See "Policy gates (opt-in by design)" below.

## Handler families

| Package | Exported constructors | Default security controls | Opt-outs / wideners |
|---|---|---|---|
| `identity` | `LoginHandler`, `RegisterHandler`, `RequestPasswordResetHandler`, `ResetPasswordHandler`, `RequestEmailVerificationHandler`, `VerifyEmailHandler`, `RequestMagicLinkHandler`, `MagicLinkLoginHandler`, `ChangePasswordHandler`, `ChangePasswordWithReissueHandler`, `RequestEmailChangeHandler`, `ConfirmEmailChangeHandler`, `DeleteAccountHandler`, `RequestPhoneVerificationHandler`, `ConfirmPhoneVerificationHandler`, `RequestRecoveryEmailHandler`, `ConfirmRecoveryEmailHandler`, `RequestPasswordResetViaRecoveryHandler` | POST-only; strict same-origin gate on every request (browser POST without Origin/Referer is rejected 403 `cross_site_blocked`); 4 KiB pre-auth body cap before the argon2 path; bounded off-path delivery fan-out (64 concurrent, 30s timeout); configured tenant resolver returning `""` fails closed 401 `unresolved_tenant`; the six credential-enrollment handlers (`Request`/`Confirm` for email change, phone and recovery email) default to the `tokens.DenyInterim` gate and refuse an interim (pre-MFA) session with 403 `assurance_required` | `WithInsecureNoOriginCheck`; `WithTrustedOrigins` (widen only); `WithMaxBodyBytes(<=0)`; `WithDeliveryConcurrency(<=0)`; `WithDeliveryTimeout(<=0)`; `WithInsecureNoAssuranceCheck` (enrollment only); `WithCredentialAssurance` (override the gate) |
| `mfa` | `EnrollHandler`, `ConfirmHandler`, `VerifyHandler`, `VerifyRecoveryHandler`, `RegenerateRecoveryCodesHandler`, `DisableHandler`, `StepUpHandler` | POST-only; strict same-origin gate; 4 KiB body cap; `EnrollHandler`/`ConfirmHandler` refuse with 403 `assurance_required` unless an assurance gate is wired (fail closed); `StepUpHandler` refuses with 500 `misconfigured` unless `WithSessionStateResolver` is wired (fail closed); `DisableHandler` and `RegenerateRecoveryCodesHandler` require AMR `mfa` step-up (enrolment is not AMR-gated — first-time enrolment would be impossible — but it is separately fail-closed on the assurance gate above; the second-factor presentation is not AMR-gated either); `WithTenantResolver` returning `""` fails closed 401 (otherwise the user resolver's tenant, `""` in single-tenant, is used) | `WithInsecureNoOriginCheck`; `WithTrustedOrigins`; `WithMaxBodyBytes(<=0)`; `WithoutStepUp` / `WithStepUpRequired(false)`; `WithInsecureNoAssuranceCheck` (enrollment); `WithInsecureEchoSessionState` (step-up); `WithTenantResolver` |
| `otp` | `IssueHandler`, `VerifyHandler` | POST-only; strict same-origin gate; 4 KiB body cap; bounded delivery (100 concurrent, 30s timeout); `WithTenantResolver` returning `""` fails closed 401 | `WithInsecureNoOriginCheck`; `WithTrustedOrigins`; `WithMaxBodyBytes(<=0)`; `WithMaxConcurrentDeliveries(<=0)`; `WithDeliveryTimeout(<=0)` |
| `oauth` | `BeginHandler`, `CallbackHandler`, `DynamicBeginHandler`, `DynamicCallbackHandler` | GET redirect flow — protected by the HMAC-signed `__Host-oauth_state` cookie (no origin gate by design); `WithStateSigningKey` required and >= 32 bytes (500 otherwise); PKCE S256 on; state bound to provider + tenant; unverified provider email refused; tenant resolver returning `""` fails closed 401 | `WithStateCookieName` + `WithCookieDomain`/`WithInsecureCookies` (drops the `__Host-` host-lock); `WithoutPKCE`; `WithAllowUnverifiedEmail`; provider fetches opt out via `WithHTTPClient`/`WithInsecureURLs` (see below) |
| `passkey` | `BeginRegistrationHandler`, `FinishRegistrationHandler`, `BeginLoginHandler`, `FinishLoginHandler`, `BeginDiscoverableLoginHandler`, `FinishDiscoverableLoginHandler`, `RenameCredentialHandler` | Ceremony handlers: HMAC-sealed `__Host-passkey_ceremony` cookie + single-use challenge store; Finish body cap 64 KiB; store-capacity refusals answer 503 `store_capacity`; `BeginRegistrationHandler`/`FinishRegistrationHandler` refuse with 403 `assurance_required` unless an assurance gate is wired (fail closed). `RenameCredentialHandler`: strict same-origin gate, `application/json` required, body cap | `WithSessionCookieName` + `WithCookieDomain`/`WithInsecureCookies`; `WithInsecureNoOriginCheck` (rename only); `WithMaxBodyBytes(<=0)`; `Config.InsecureNoChallengeStore`; `WithInsecureNoAssuranceCheck` (registration) |
| `authflow` | `StepUpHandler` | POST-only; strict same-origin gate; 4 KiB body cap; signed flow-token (`state`/`flow`) verification before the second factor is accepted | `WithInsecureNoOriginCheck`; `WithTrustedOrigins`; `WithStepUpMaxBodyBytes(<=0)` |
| `sessions` | `RequireSession` | Cookie-authenticated unsafe methods (POST/PUT/PATCH/DELETE) rejected unless same-origin (Origin/Referer host == request host or allowlisted), 403 `cross_site_blocked`; Bearer-header auth exempt (non-ambient); `__Host-session_token` default cookie; tenant resolver returning `""` fails closed 401 | `WithInsecureNoOriginCheck`; `WithTrustedOrigins`; `WithCookieName`; `WithTenantResolver` |
| `tokens` | `RefreshHandler`, `LogoutHandler`, `RequireAuth`, `ContextMiddleware` | Cookie-driven POST handlers: strict same-origin gate. `RequireAuth`/`ContextMiddleware`: access-token verification (alg-pinned JWT) with `WithAuthTenantResolver` failing closed 401; optional AMR/scope/max-auth-age/password-change/access-token-revocation gates | `WithInsecureNoOriginCheck`; `WithTrustedOrigins`; `WithTenantResolver` (handlers); `WithAuthTenantResolver` (middleware); `WithAccessTokenRevocation` (opt-in, no lookup when unset) |
| `tokens/basic` | `RefreshHandler`, `LogoutHandler`, `RequireAuth`, `ContextMiddleware` | `C=struct{}` facade over `tokens`; inherits the same defaults | same as `tokens` |
| `origin` | `Middleware` | Wraps an application-owned handler with the strict same-origin gate on unsafe methods (exact host match after normalization; missing Origin/Referer and cross-scheme `http`-on-https rejected 403 `cross_site_blocked`); safe methods (`GET`/`HEAD`/`OPTIONS`) pass | `WithInsecureNoOriginCheck`; `WithTrustedOrigins` (widen only) |
| `webapp` | `NewWebApp` | Composes `identity` register/login + `tokens/basic` refresh/logout; forwards `Config.TrustedOrigins` and a non-empty `Config.Tenant` to both families; per-client-IP `ratelimit.TokenBucket` shared across all mounted routes (burst 20, refill 6s, `ClientIP`, 429 + `Retry-After`) | `Config.InsecureNoOriginCheck`; `Config.InsecureNoRateLimit`; `Config.CookieDomain`; `Config.RateLimiter` (replacement, not an opt-out) |

## Outbound-HTTP constructors

| Constructor | Default control | Opt-out / alternative |
|---|---|---|
| `oauth.SafeHTTPClient()` | Dial-time SSRF guard: rejects loopback, link-local (incl. cloud metadata), private/RFC1918, CGN, unique-local, unspecified and multicast addresses *after DNS resolution* (rebinding-safe); ignores `HTTP(S)_PROXY`; 10s timeout; never follows 3xx | None — build an explicit `*http.Client` for a custom transport |
| `oauth.New(...)` (`*Provider`) | Token exchange (carries `client_secret`) and userinfo fetch default to `oauth.SafeHTTPClient()`; non-https auth/token endpoints are a deferred config error | `WithHTTPClient` (custom client; `CheckRedirect` is forced off); `WithInsecureURLs` (plain 10s client + non-https allowed; local dev only) |
| `oauth.WithOIDC` / `oauth.OIDCConfig` | Discovery + JWKS fetches default to `oauth.SafeHTTPClient()`; issuer/JWKS host must match; `alg`/`kid` pinned | `OIDCConfig.HTTPClient` |
| `oauth/providers.OIDC(...)` | Discovery + JWKS fetch default to `oauth.SafeHTTPClient()`; discovered endpoints re-validated; the resulting Provider's token/userinfo fetches default to the safe client via `oauth.New` | `WithDiscoveryHTTPClient`; `WithInsecureDiscoveryURLs`; `oauth.WithHTTPClient` / `oauth.WithInsecureURLs` |
| `oauth/providers.{Google,GitHub,GitLab,GitLabSelfHosted,Apple,Auth0,Cognito,Discord,Facebook,Keycloak,LinkedIn,Microsoft,Okta,OktaCustom}` | Thin wrappers over `oauth.New`: token + userinfo fetches default to `oauth.SafeHTTPClient()` | `oauth.WithHTTPClient`; `oauth.WithInsecureURLs` (passed through) |
| `passwords/breach/hibp.New(...)` | Fixed public endpoint (`https://api.pwnedpasswords.com`), SHA-1 k-anonymity (only a 5-char hash prefix leaves the process), 10s timeout, 4 MiB response cap, fails closed on upstream error | `WithBaseURL` (self-hosted mirror); `WithHTTPClient`; `WithFailOpen` |

Registration-time URL validators (not constructors): `oauth.ValidateExternalURL`,
`oauth.ValidateOIDCEndpointURL` — coarse https/internal-IP checks used before a tenant-supplied
URL is stored or fetched; the dial-time guard in `SafeHTTPClient` remains authoritative.

## Policy gates (opt-in by design)

These are not defaults the library can pick for you: they encode *your* product's rule about when a
second factor is required. Absent, they do nothing.

| Gate | Where | Absent means |
|---|---|---|
| `identity.WithMFAGate(checker)` | `identity.LoginHandler`, `identity.MagicLinkLoginHandler` | a correct password yields a full access+refresh pair, whether or not the account has an enrolled factor |
| `oauth.WithMFAGate(checker)` | `oauth.CallbackHandler`, `oauth.DynamicCallbackHandler` | a successful provider authorization yields a full pair, whether or not the account has an enrolled factor |
| `tokens.WithRequiredAMR(tokens.AMRMFA)` | any route behind `tokens.RequireAuth` / `ContextMiddleware` | any verified token reaches the route, at any assurance level |
| `tokens.WithDenyInterim()` | any route behind `RequireAuth` / `ContextMiddleware` | an interim (pre-second-factor) token reaches the route |

Wired, the first two make an enrolled account receive only the short-lived interim access token —
no refresh cookie — and the client completes the factor through `mfa.StepUpHandler`. `mfa.Service`
and `identity.Service` satisfy the gate interface, so wiring is `identity.WithMFAGate(mfaSvc)`.

### Credential-enrollment gates (fail-closed by default)

Unlike the product-policy gates above, *which session may enroll a credential* is a composition
rule the library judges on its own, so the handlers enforce it by default:

| Handler family | Default | Opt-out | Canonical gate |
|---|---|---|---|
| `passkey.BeginRegistrationHandler` / `FinishRegistrationHandler` | 403 `assurance_required` unless an assurance gate is wired | `passkey.WithInsecureNoAssuranceCheck()` | `passkey.WithCredentialAssurance(tokens.DenyInterim)` |
| `mfa.EnrollHandler` / `ConfirmHandler` | 403 `assurance_required` unless an assurance gate is wired | `mfa.WithInsecureNoAssuranceCheck()` | `mfa.WithCredentialAssurance(tokens.DenyInterim)` |
| `identity`'s six enrollment handlers (email change, phone, recovery email) | `tokens.DenyInterim` (denies only a positively-interim session; token-less session-based apps and fully-elevated sessions pass) | `identity.WithInsecureNoAssuranceCheck()` | default, or `identity.WithCredentialAssurance(...)` |
| `mfa.StepUpHandler` (mints the post-factor pair) | 500 `misconfigured` unless an authoritative account-state resolver is wired | `mfa.WithInsecureEchoSessionState()` | `mfa.WithSessionStateResolver(idSvc.(issuance.Resolver))` (the concrete identity service implements it; the exported `identity.Service` interface does not expose it) |

`tokens.DenyInterim` is the shared, non-generic gate (`func(*http.Request) error`): `RequireAuth`
and `ContextMiddleware` record whether the verified token is interim, and `DenyInterim` reads that
marker, so the same predicate works for every handler family without exposing `Claims[C]`.

Wiring none of the product-policy gates is a valid configuration: an application that hands MFA to
its users as an optional extra (a security setting they may enable) wants exactly that. It is worth
being explicit about which of the two you are shipping, because mounting the `mfa` handlers alone
changes no login outcome: users can enrol and confirm an authenticator and still sign in with the
password alone.
