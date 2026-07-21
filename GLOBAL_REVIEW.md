# egauth — Global Adversarial Review

> **Verdict: PROMOTE with fixes.** No CONFIRMED finding is a direct authentication *bypass*; every one of the eight fails **closed** (broken feature, dropped control, availability outage, or audit/attribution gap) rather than open. The one **High** — Google OIDC id_token validation being impossible — is a broken headline feature, not a hole. The library's core crypto (JWT alg-confusion defense, argon2id, constant-time compares, CSRF/origin fail-closed, tenant scoping) held up under adversarial reading.

Whole-project review (not a diff) of module `github.com/JLugagne/egauth` (Go 1.26, ~54k LOC, 3 modules: core, `adapters/pgx`, `adapters/otel`). Methodology: review-detractor (refute-first) — 12 focused Opus agents, one per unit, 3 in parallel per wave. Deterministic tooling was run centrally; each unit was then read adversarially. Every CONFIRMED finding below was **re-verified by hand against the source** by the reviewer.

**Totals:** 8 confirmed (blocking) · 37 risks (advisory) · 94 nits (advisory).

---

## 1. Deterministic tooling (baseline)

| Check | Core | adapters/pgx | adapters/otel |
|---|---|---|---|
| `gofmt -l` | clean | clean | clean |
| `go build ./...` | ok | ok | ok |
| `go vet ./...` | clean | clean | clean |
| `go test ./...` | 1384 pass / 44 pkg | pass (`-short`) | pass |
| `golangci-lint` (default) | 0 issues | — | — |

No `.golangci.yml` exists in the repo, so the strict suite the skill assumes is not configured; a broad ad-hoc linter run surfaced ~91 core / 27 pgx / 4 otel low-severity items (mostly test files: `revive` exported-comment on mocks, `unparam` in helpers, `usestdlibvars`). `go fix` modernizers flagged hand-rolled loops replaceable with `slices` (e.g. `actor.go` `HasScope`). The three `nilerr` hits in `identity/service.go` were investigated and are **not bugs** — each is a deliberate enumeration-uniform return path.

---

## 2. Confirmed findings (blocking)

Ranked by severity. Each was reproduced-in-reasoning by the agent and verified against source by the reviewer.

| # | Sev | Unit | Finding | Location |
|---|---|---|---|---|
| C1 | **HIGH** | oauth | Google OIDC id_token validation is impossible: sameHost issuer↔JWKS binding rejects Google's own jwks_uri, and the documented Google+WithOIDC setup always fails login | `oauth/providers/google.go:25` |
| C2 | **MEDIUM** | tokens-core | actorFromClaims drops Actor.KeyID and mis-sets Actor.UserID for Service/PAT JWTs, violating the Actor contract | `tokens/middleware.go:326` |
| C3 | **MEDIUM** | identity | Re-lockout after expiry never emits AccountLocked (brute-force audit blind spot) | `identity/memory/store.go:389` |
| C4 | **MEDIUM** | sessions | WithNoMaxLifetime() then WithMaxLifetime(d) leaves the absolute-lifetime cap disabled, contradicting docs and silently dropping a security control | `sessions/service.go:250` |
| C5 | **MEDIUM** | mfa-otp | IssueHandler synchronous svc.Issue creates an account-existence timing oracle it claims not to have | `otp/handlers.go:190` |
| C6 | **MEDIUM** | keystore | Re-provision after RevokeTenantKeys is a silent no-op; documented recovery leaves tenant permanently keyless | `keystore/manager.go:119` |
| C7 | **MEDIUM** | pgx | oauth GetProvider decrypts client_secret before the cache check, so a transient KEK failure defeats a warm cache and every cached OIDC login pays a KEK round-trip | `adapters/pgx/oauth/store.go:162` |
| C8 | **LOW** | passkey | ErrAttestationRejected returns HTTP 500 instead of a 4xx client error | `passkey/handlers.go:344` |

### C1 · [HIGH] Google OIDC id_token validation is impossible: sameHost issuer↔JWKS binding rejects Google's own jwks_uri, and the documented Google+WithOIDC setup always fails login

- **Unit:** oauth  ·  **Location:** `oauth/providers/google.go:25`  ·  **Verified:** ✅ against source
- **Failure path:** GoogleIssuer = "https://accounts.google.com" and GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs" live on DIFFERENT hosts. Repro exactly as documented in google.go:21-23: p := providers.Google(id, secret, oauth.WithOIDC(oauth.OIDCConfig{Issuer: providers.GoogleIssuer, JWKSURL: providers.GoogleJWKSURL})). Inside WithOIDC → newOIDCVerifier (oauth/oidc.go:107): jwksOverride="https://www.googleapis.com/..."; at oidc.go:125 !sameHost(jwksOverride, cfg.Issuer) is TRUE (sameHost at oidc_discovery.go:52-63 requires exact case-insensitive host equality; "www.googleapis.com" != "accounts.google.com"), so newOIDCVerifier returns ErrJWKSHostMismatch. WithOIDC (provider.go:85-100) records p.configErr and leaves p.oidc nil. At runtime Provider.Exchange (provider.go:215-217) returns configErr on the FIRST line, so CallbackHandler (handlers.go:224-228) always fails with 'exchange_failed'. The discovery fallback is equally broken: leaving JWKSURL empty makes discoverJWKSURL fetch accounts.google.com/.well-known/openid-configuration, get jwks_uri=www.googleapis.com/..., then fail the identical sameHost check at oidc_discovery.go:114 (ErrJWKSHostMismatch) inside verify(). Either way, Google id_token validation can never succeed.
- **Impact:** OIDC id_token validation — the package's headline security feature — is completely unusable for Google, one of the most common IdPs, and for any spec-compliant issuer whose jwks_uri host differs from the issuer host (the OIDC spec permits this). Following the shipped documentation yields a provider on which every login attempt fails at the callback with 'exchange_failed'. Fails closed (not an auth bypass), so severity is high rather than critical, but the feature is broken and no test covers it.

### C2 · [MEDIUM] actorFromClaims drops Actor.KeyID and mis-sets Actor.UserID for Service/PAT JWTs, violating the Actor contract

- **Unit:** tokens-core  ·  **Location:** `tokens/middleware.go:326`  ·  **Verified:** ✅ against source
- **Failure path:** An application uses the documented API-key-backed JWT flow: issue a token with Claims{Kind: egauth.Service, Subject: keyID, Scopes:...} (Claims.Kind's doc: 'set by the issuer when minting API-key-backed tokens (PAT or Service) ... used by actorFromClaims to propagate the classification'), the JWT carries Kind (jwt/issuer.go:435) but there is NO KeyID claim. A request with that Bearer token hits RequireAuth (the documented RequireMachine use). actorFromClaims returns egauth.Actor{UserID: claims.Subject, TenantID, Kind: Service, Scopes} — KeyID is left uuid.Nil and UserID is set to the KEY's own ID. This contradicts egauth.Actor's field docs ('KeyID Non-zero for PAT and Service actors'; 'for Service actors the subject is the key's own ID, which is stored in KeyID rather than [UserID]') and diverges from ActorFromAPIKey (actor.go:38-40) which for KeyTypeService sets KeyID=key.ID and leaves UserID zero. So the same Service principal yields KeyID=keyID,UserID=Nil via VerifyAPIKey but KeyID=Nil,UserID=keyID via the JWT middleware.
- **Impact:** Broken/ambiguous machine-principal attribution: an app that audits or authorizes machine actions by actor.KeyID (as the Actor docs instruct) reads uuid.Nil on the middleware path, and an app that treats a non-zero actor.UserID as 'a human user' sees the key's UUID for a Service actor. IsMachine()/WithRequiredKind still work (Kind-based), so exploitability is limited to attribution/authorization confusion rather than direct escalation, but the two code paths produce contradictory Actor shapes for the same credential.

### C3 · [MEDIUM] Re-lockout after expiry never emits AccountLocked (brute-force audit blind spot)

- **Unit:** identity  ·  **Location:** `identity/memory/store.go:389`  ·  **Verified:** ✅ against source
- **Failure path:** FailedAttempts is only zeroed on successful auth (service.go:589) or password update (memory/store.go:278) — never when a lock expires. Repro with WithLockout(threshold=2, short duration): fail twice -> IncrementFailedAttempts sets FailedAttempts=2, before=1, justLocked = 1<2 = true -> service.go:581 emits AccountLocked (once). Wait out the lock window so LockedUntil.After(now) is false (service.go:549). Fail once more: Authenticate proceeds to Compare, calls IncrementFailedAttempts with before=2, FailedAttempts=3, 3>=2 so LockedUntil is re-set (account is locked AGAIN), but justLocked = before(2) < threshold(2) = false. service.go:581 therefore does NOT emit AccountLocked, even though the account just transitioned unlocked->locked. Every lockout cycle after the first is silent.
- **Impact:** A SIEM/alert that keys on the AccountLocked event sees only the very first lockout for an account. An attacker who paces guesses to one per lock-window keeps the account perpetually locked while generating zero further lock events, and a legitimate user's repeated lockouts are invisible to monitoring. This defeats the documented once-per-lock-crossing contract (store.go:135-142) for all cycles past the first because `before` is permanently >= threshold once the counter is never reset on expiry.

### C4 · [MEDIUM] WithNoMaxLifetime() then WithMaxLifetime(d) leaves the absolute-lifetime cap disabled, contradicting docs and silently dropping a security control

- **Unit:** sessions  ·  **Location:** `sessions/service.go:250`  ·  **Verified:** ✅ against source
- **Failure path:** WithNoMaxLifetime (service.go:264-269) sets s.noMaxLifetime=true AND s.maxLifetime=0. WithMaxLifetime (service.go:250-257) only sets s.maxLifetime=d (when d>0); it never clears s.noMaxLifetime. absoluteDeadline (service.go:274-279) returns 'no cap' when `s.noMaxLifetime || s.maxLifetime<=0`. Repro: NewService(store, WithNoMaxLifetime(), WithMaxLifetime(1*time.Hour)) yields noMaxLifetime=true, maxLifetime=1h -> absoluteDeadline returns (zero,false) -> ValidateSession/clampExpiry never enforce a cap. A developer who disabled then re-enabled a cap (order No-before-Max) gets NO absolute cap: a stolen-but-kept-warm token can be Touched indefinitely and lives forever.
- **Impact:** A configured absolute session-lifetime cap is silently ignored. The WithMaxLifetime doc (service.go:262-263) explicitly promises 'the last option wins', but that only holds for the Max-before-No order; the No-before-Max order leaves the secure control off. Security-relevant misconfiguration that fails open (no cap) with no error or warning.

### C5 · [MEDIUM] IssueHandler synchronous svc.Issue creates an account-existence timing oracle it claims not to have

- **Unit:** mfa-otp  ·  **Location:** `otp/handlers.go:190`  ·  **Verified:** ✅ against source
- **Failure path:** IssueHandler resolves the subject, then only when ok==true calls svc.Issue synchronously on the response path (line 191) before responding; when ok==false it skips svc.Issue entirely and responds immediately (line 197). svc.Issue performs a store write (SaveOTP -> an INSERT/UPSERT round-trip on the documented pgx production backend, ~ms). The subjectResolver runs in both branches so its latency is common-mode; the ONLY differential is the Issue store write, which happens exclusively for a resolved (existing) subject. Concrete repro: attacker POSTs email A (maps to a real subject -> ok=true -> extra DB write) and email B (no subject -> ok=false -> no write); over many samples the A responses are measurably slower, revealing which emails have accounts. This defeats the guarantee stated verbatim in the doc comment (lines 161-166): 'ALWAYS responds uniformly ... so it leaks no account-existence signal.' The delivery was correctly detached to avoid a timing oracle, but the Issue store write was left on the response path.
- **Impact:** Account/subject enumeration via response-latency measurement against the OTP issue endpoint, contradicting a documented security guarantee. Negligible on the in-memory store, but measurable on the recommended pgx backend where Issue is a network round-trip. Enables targeted follow-on attacks (credential stuffing, phishing) against confirmed-existing accounts.

### C6 · [MEDIUM] Re-provision after RevokeTenantKeys is a silent no-op; documented recovery leaves tenant permanently keyless

- **Unit:** keystore  ·  **Location:** `keystore/manager.go:119`  ·  **Verified:** ✅ against source
- **Failure path:** RevokeTenantKeys -> memory Store.RevokeTenantKeys (memory/store.go:203) sets s.tenants[tenantID] = make(map...), i.e. the tenant record STAYS PRESENT with zero keys. The RevokeTenantKeys doc comment (manager.go:209) states 're-provision or renew to restore signing'. But ProvisionTenant (manager.go:115-121) gates idempotency on store.TenantExists, and memory TenantExists (store.go:75) returns true for the present empty map. Repro: mgr.ProvisionTenant(ctx,"t"); mgr.RevokeTenantKeys(ctx,"t"); mgr.ProvisionTenant(ctx,"t") -> returns nil with NO key minted and NO EventTenantProvisioned; then mgr.ActiveSigningKey(ctx,"t") -> ErrNoActiveKey forever. An operator who follows the documented 're-provision' recovery sees a success return yet the tenant can never issue tokens (auth outage). Only the undocumented-as-primary 'renew' half works.
- **Impact:** A tenant is left permanently unable to sign JWTs after an emergency key revocation when the operator uses the documented ProvisionTenant recovery, because that call returns success while doing nothing. Availability/correctness outage masked by a false-success. Root cause: TenantExists conflates 'tenant record present' with 'tenant has an active key', and revoke does not clear the record. Fix: either base ProvisionTenant idempotency on the presence of an active key rather than TenantExists, make RevokeTenantKeys remove the tenant record, or correct the doc to state re-provision does not restore signing (renew does).

### C7 · [MEDIUM] oauth GetProvider decrypts client_secret before the cache check, so a transient KEK failure defeats a warm cache and every cached OIDC login pays a KEK round-trip

- **Unit:** pgx  ·  **Location:** `adapters/pgx/oauth/store.go:162`  ·  **Verified:** ✅ against source
- **Failure path:** GetProvider fetches the row (QueryRow) then, at lines 162-173, base64-decodes and s.kek.Open()s the client_secret UNCONDITIONALLY, before the providerCache lookup at lines 177-182. On a cache HIT the freshly-decrypted clientSecret is discarded (line 180 returns cp.provider). Repro: (1) GetProvider(tenant,provider) builds and caches the provider; (2) a second GetProvider with the row unchanged reaches line 168 again — if s.kek.Open returns a transient error (KMS/network blip, common for a remote KEK), line 170 returns that error and the valid cached provider at line 178 is never reached, so OIDC login fails despite a warm cache. Even on success, every single OIDC login performs a KEK.Open (a network call for a KMS-backed KEK), which the cache was partly meant to avoid — TestGetProviderCachesBuiltProvider asserts 2 DB reads for 2 calls, confirming per-call work on the hot path.
- **Impact:** OIDC logins for an already-cached provider become hard-dependent on per-request KEK availability and latency; a brief KEK outage takes down logins that a warm cache should have served, and every login incurs an avoidable decrypt. Fix: move the cache-hit check (compare updatedAt) ahead of the decode/decrypt, and only Open the secret on a cache miss/stale entry.

### C8 · [LOW] ErrAttestationRejected returns HTTP 500 instead of a 4xx client error

- **Unit:** passkey  ·  **Location:** `passkey/handlers.go:344`  ·  **Verified:** ✅ against source
- **Failure path:** Configure a Service with Attestation.ProhibitedAAGUIDs (or a PermittedAAGUIDs allow-list). A client registers with an authenticator whose AAGUID is on the deny-list / off the allow-list. FinishRegistrationHandler calls svc.FinishRegistration, which maps the go-webauthn policy_restriction error to ErrAttestationRejected (service.go:215-218) and returns it. cfg.fail(w, err) runs the switch, but ErrAttestationRejected is not one of the cases (ErrSessionInvalid/ErrNoCredentials/ErrCredentialCloned/ErrCredentialNotFound/ErrCredentialExists/*protocol.Error), so it falls through to the default branch and emits http.Error(w, "internal_error", 500). A legitimate client whose authenticator is refused by policy therefore receives a 500 server error rather than a 4xx client/policy rejection, mislabeling a client-side condition as a server fault and generating false operator alerts.
- **Impact:** Attestation-policy rejections (a normal, client-driven outcome) are surfaced as HTTP 500 internal_error instead of a 4xx, causing incorrect client behavior and spurious 5xx alerting. No data exposure. Not covered by any handler-level test (attestation_test.go only asserts the service-level error).

---

## 3. Risks (advisory — reasoned, not reproduced)

### OAuth / OIDC (`oauth/`, `oauth/providers/`)

- **requestScheme trusts X-Forwarded-Proto unconditionally when deriving redirect_uri** — `oauth/handlers.go:317`  
  When WithRedirectURL is not set, resolveRedirectURL (handlers.go:306-311) builds redirect_uri from requestScheme(r)+"://"+r.Host+r.URL.Path, and requestScheme blindly honours a client-supplied X-Forwarded-Proto header (and r.Host). Behind a misconfigured/absent trusted proxy an attacker could influence the scheme/host used in the authorization request and the token-exchange redirect_uri. Real impact is bounded because the provider enforces the registered redirect_uri, and the docs say to set WithRedirectURL in production — hence a risk, not confirmed. Consider only trusting X-Forwarded-Proto behind an explicit proxy opt-in.
- **stringifyID uses float64 for numeric sub/id — precision loss above 2^53 can collide or shift identities** — `oauth/providers/gitlab.go:75`  
  stringifyID (also used by oidcUserInfoFetcher in okta.go for Okta/Auth0/Keycloak/Cognito/generic-OIDC userinfo) decodes a numeric JSON sub as float64 then strconv.FormatInt(int64(id),10). JSON numbers above 2^53 lose integer precision, so two distinct large numeric subjects could map to the same ProviderID (identity collision → account takeover) or a subject's ProviderID could change. Most listed IdPs use string subs so exposure is limited; still, decoding into json.Number (or json.RawMessage) and rejecting non-integers would be safer.

### Tokens — core (`tokens/`: handlers, middleware, cookies)

- **Claims.Groups and Claims.Roles are unreachable on the RequireAuth/WithGate path** — `tokens/middleware.go:183`  
  The JWT carries Groups and Roles (jwt/issuer.go:437-438) and VerifyAccessTokenForTenant returns them in Claims, but RequireAuth invokes next(w, r, actor, claims.Custom) and actorFromClaims copies only Scopes onto the Actor. Neither the AuthenticatedHandlerFunc nor WithGate's predicate (which receives only (egauth.Actor, C)) can observe Claims.Groups/Roles; role/group-based authorization is impossible unless the app duplicates them into the custom-claims type C. Only ContextMiddleware+ClaimsFromContext exposes the full Claims. This is a silent capability gap for the primary middleware surface rather than a memory-safety bug.
- **Auto-refresh consumes a rotation and rewrites cookies before a post-refresh gate rejection** — `tokens/middleware.go:274`  
  In serveAuthenticated's auto-refresh branch the new pair is minted and SetAccess/SetRefresh are written, then stepUpSatisfied/scopesSatisfied/passwordChangeBlocked/gate are evaluated and may return 403. Each request to a gated-but-refreshable route with an expired access token therefore burns one refresh rotation even though the request is rejected. Behaviorally acceptable (the client keeps a valid fresh cookie and AuthTime is preserved so step-up is still enforced), but a high-frequency gated endpoint drives continuous rotation churn; worth confirming this is intended.

### Identity (`identity/`)

- **Timing enumeration oracle on unauthenticated Request* endpoints** — `identity/service.go:623`  
  RequestPasswordReset (and RequestMagicLink:1036, RequestPasswordResetViaRecovery:1264) do measurably more synchronous work for an existing account (FindUserByEmail hit + FindIdentitiesByUserID + CreateVerificationToken, which runs crypto/rand + SHA-256 + a store insert) than for an unknown account (FindUserByEmail miss -> early return at :627). Unlike Authenticate, there is NO decoy work to equalize this. dispatchDelivery correctly moves the Mailer latency off-path (handlers.go:457 context.WithoutCancel), and the comment at handlers.go:440 claims that removes the side channel, but it does not address the token-minting asymmetry that stays in the request path. For a security library that goes to lengths (decoyHash) to equalize Authenticate, this is an inconsistent gap. Not marked confirmed because a single extra DB round-trip + hash is likely below network-jitter noise for a remote attacker.
- **UpdateIdentityPassword / SetTemporaryPassword lack a live-user gate on the memory store** — `identity/memory/store.go:270`  
  UpdateIdentityPassword matches the password identity purely by UserID+tenant+provider and never checks the owning user's DeletedAt. DeleteUser (store.go:166) soft-deletes the user and anonymizes the password ProviderID but keeps the identity row and its PasswordHash. So SetTemporaryPassword (service.go:1369, no liveness gate) and ResetPassword succeed against a soft-deleted account's identity and re-arm a usable hash. Not exploitable via login on this store (the user email is anonymized to a random UUID, so FindUserByEmail can't reach it), but it diverges from every other write path which gates on DeletedAt, and may diverge from the pgx backend's `WHERE deleted_at IS NULL` join — a store-contract inconsistency.
- **ConfirmRecoveryEmail does not re-check independence from the primary email at confirm time** — `identity/service.go:1215`  
  RequestRecoveryEmail rejects a recovery email equal to the primary (ErrRecoveryEmailIsPrimary, :1201), but ConfirmRecoveryEmail sets it unconditionally. If the primary email is changed to the pending recovery address (via ConfirmEmailChange) between request and confirm, the recovery channel is set equal to the new primary, defeating the documented independence invariant. Low severity: exercising this requires the same actor to prove control of the same address twice, so it is a self-inflicted edge case, not a takeover vector.

### Sessions (`sessions/`)

- **Rotate, BindUser and CreateSession emit no audit event; only logout is audited** — `sessions/service.go:164`  
  WithEventSink is wired but emit() is only called from RevokeSession (service.go:226) and RevokeAllForUser (service.go:298). Rotate (privilege-change / step-up, line 164) and BindUser (anonymous->authenticated login, line 190) are exactly the security-significant transitions an audit trail wants, and CreateSession (line 99) is session establishment. None emit. A SIEM fed by the event.Sink sees logouts but never logins, rotations, or privilege upgrades from this module. Likely a deliberate scope decision (identity may emit login events) but worth confirming the audit story is complete.
- **RevokeSession is not idempotent while RevokeAllForUser is** — `sessions/service.go:217`  
  RevokeSession calls FindSessionByHash (line 217) and returns its error directly; an already-expired or unknown token yields ErrSessionNotFound. RevokeAllForUser is idempotent (returns nil for a user with no sessions). A logout handler that receives a double-submit, or logs out a token that just crossed idle/absolute expiry, gets a spurious error and cannot easily distinguish 'already logged out' from a real failure. Also, no Logout event is emitted on that path since the function returns before emit().
- **Memory store expiry/eviction uses wall-clock time.Now() instead of the service's injected clock** — `sessions/memory/store.go:39`  
  FindSessionByHash (store.go:39), DeleteExpired (store.go:200) and evictOne (store.go:238) all call time.Now(). The service ValidateSession uses s.now() (WithClock). In production both are wall clock so behaviour agrees, but the two clocks are independent: any deployment that ever set a non-wall clock, or a test that freezes the service clock, gets divergent expiry decisions (the store may evict a row the service still considers live, or retain one the service rejects). The Store contract documents 'expired => not found' but pins it to real time, not the caller's clock.
- **BoundedStore.evictOne can evict a live, in-use session to admit a new one** — `sessions/memory/store.go:249`  
  When the cap is reached and no expired session exists, evictOne (store.go:249-266) deletes the soonest-expiring LIVE session. Under sustained load at the cap this silently logs out active users (their next request 401s) to make room for new sessions — an availability/logout footgun. Documented in NewBoundedStore, but a caller sizing the cap too small gets surprising forced logouts rather than a CreateSession error.
- **Module never sets the session cookie, so Secure/HttpOnly/SameSite are entirely the consumer's responsibility** — `sessions/middleware.go:35`  
  RequireSession only READS the cookie; there is no Set-Cookie helper. The __Host- 'secure by default' guarantees only apply if the consumer actually writes the cookie with the __Host- name plus Secure/HttpOnly/SameSite. A consumer that sets a plain, non-HttpOnly cookie gets none of the advertised hardening, and nothing in this module enforces it. Doc-only mitigation; consider shipping a cookie-writer helper.

### MFA & OTP (`mfa/`, `otp/`)

- **A valid recovery code is rejected while the TOTP factor is locked out** — `mfa/service.go:309`  
  VerifyRecoveryCode gates on the shared TOTP attempt budget: when an enrollment exists it calls reserveAttempt/overLimit BEFORE ConsumeRecoveryCode (lines 309-320). Once FailedAttempts >= maxAttempts (IncrementTOTPAttempts returns count+1 without decaying, memory/store.go:97-100), overLimit is true and the method returns ErrTooManyAttempts before ever checking the recovery code. So an attacker (or the user) who burns the TOTP attempt budget with wrong codes also locks out the recovery-code escape hatch for the whole LockoutDuration (default 15m). Recovery codes are the intended fallback when the authenticator is unavailable; coupling them to the TOTP lockout lets a party who knows only the password (interim/step-up session) deny the victim BOTH factors. It is a deliberate, commented design choice (brute-force parity) and the 80-bit codes are not realistically guessable, so it is a DoS tradeoff rather than a break — but it deserves an explicit product decision.
- **Concurrent verification floods amplify AccountBlocked events** — `otp/service.go:135`  
  Under a burst of N concurrent wrong-code verifies, IncrementOTPAttempts hands out counts 1..N; every caller with n > maxAttempts (otp/service.go:135-139) and the caller at n == maxAttempts (line 142-146) each emit an AccountBlocked event, so one burst against a single code emits up to N duplicate events. mfa has the same shape (service.go:270-273 and 317-320 emit on every over-limit reserve). A sink that pages/writes per event can be amplified by an attacker who can drive concurrency, and duplicate events pollute audit logs. Not a correctness bug, but worth de-duping (emit once at the transition into the blocked state).
- **Concurrent double-ConfirmTOTP hands one caller unstored recovery codes** — `mfa/service.go:245`  
  Two concurrent ConfirmTOTP calls with the same valid code both pass validateTOTP, both SaveTOTP, then both call mintRecoveryCodes -> ReplaceRecoveryCodes. The second Replace overwrites the first, so the first caller receives a recovery-code set that is never persisted and will not verify. Requires a self-inflicted concurrent confirm on one account, so low impact, but the returned codes silently do not work.

### Keystore (`keystore/`)

- **No zeroization of opened plaintext key material** — `keystore/resolve.go:73`  
  openKey replaces key.Secret with the KEK-decrypted plaintext (HMAC secret or PKCS#8 DER private key) and hands it out to callers (ActiveSigningKey/VerificationKeys/Keyset/JWKS), which pass it into jwt signers. Nothing ever wipes these buffers; they live as GC-managed heap for the lifetime of the caller's references and may be swapped to disk or appear in a core dump. The KEK/store docs promise material is sealed 'at rest', which holds, but the runtime plaintext is retained without a subtle/mem-wipe. This is likely an accepted tradeoff (per the project's documented secret-handling model / SECURITY.md) since Go makes reliable zeroization hard, but for a security library it is worth an explicit decision/comment rather than silence.
- **Nondeterministic active-key selection on CreatedAt ties** — `keystore/memory/store.go:112`  
  ActiveSigningKey picks the active key with the latest CreatedAt using k.CreatedAt.After(best.CreatedAt); on an exact tie the winner is whichever the (randomized) map iteration reaches first. Not reachable through the normal Manager flow (RenewSigningKey retires the prior active key before adding the new one, so at most one active key exists), but a fixed test clock plus a direct Store.PutSigningKey of two non-retired keys with equal CreatedAt would yield a nondeterministic active key. Defensive tie-break (e.g. by KeyID) would make it total.
- **DeleteTenant emits EventTenantDeleted for a tenant that never existed** — `keystore/manager.go:233`  
  DeleteTenant always emits EventTenantDeleted after store.DeleteTenant, but memory Store.DeleteTenant (store.go:208-213) is a silent no-op for an absent tenant (delete on missing map key). So DeleteTenant on a never-provisioned tenant, and the second call in an idempotent double-delete, both emit a 'tenant.deleted' security event with nothing deleted, polluting the audit trail. Consider gating emission on whether a record was actually removed.

### Adapter — Postgres (`adapters/pgx/`)

- **keystore CreateTenant loses the ErrTenantExists guarantee on the non-transactional fallback path** — `adapters/pgx/keystore/store.go:58`  
  When s.db does not satisfy txBeginner (lines 58-61) CreateTenant runs createTenantChecked with no advisory lock and no transaction, reintroducing the exact TOCTOU the advisory-lock path fixes: two concurrent CreateTenant for the same tenant both see TenantExists==false, then both PutSigningKey (INSERT ... ON CONFLICT DO UPDATE) succeed, so neither returns keystore.ErrTenantExists and the 'first writer wins' contract is silently violated. Not reproducible in normal deployments because *pgxpool.Pool and pgx.Tx both implement Begin, so the locked path is always taken — but any custom DBQuerier wrapper without Begin degrades unsafely and silently.
- **mfa SaveTOTP ON CONFLICT overwrites last_used_step, which can reset TOTP replay protection** — `adapters/pgx/mfa/store.go:71`  
  The upsert's DO UPDATE sets last_used_step = EXCLUDED.last_used_step (line 74). MarkTOTPUsed advances this counter to block step replay; if any caller re-invokes SaveTOTP for an already-enrolled user carrying a stale/zero LastUsedStep (e.g. to update metadata), the step counter is rolled back and a previously-consumed TOTP code becomes replayable within its window. Safe only as long as the service uses SaveTOTP exclusively for enroll/replace (fresh secret) and never for in-place metadata edits — a fragile invariant not enforced by the store.
- **IncrementFailedAttempts re-extends locked_until after expiry and never re-fires justLocked** — `adapters/pgx/identity/store.go:471`  
  failed_attempts is never zeroed when a lock expires (only ResetFailedAttempts on success clears it). After locked_until passes, the service (service.go:549) lets the next failed attempt through to IncrementFailedAttempts; with failed_attempts already >= threshold, the CASE at lines 471-474 sets locked_until = now()+duration again on the FIRST wrong password, re-locking for the full duration. Meanwhile the RETURNING predicate (line 477) is true only on the exact crossing (post==threshold), so justLocked is false on every re-lock. If callers key a 'your account was locked' notification off justLocked, re-locks after expiry are silent. Likely intended sliding-window behavior, but the silent re-lock/no-event asymmetry is worth confirming against the memory store.
- **mfa transactional helpers silently lose atomicity/serialization on the non-beginner fallback** — `adapters/pgx/mfa/store.go:185`  
  IncrementTOTPAttempts (185-187), ReplaceRecoveryCodes (229-231) and ConsumeRecoveryCode (271-273) each fall back to running their multi-statement logic directly on s.db when it lacks Begin. In that path IncrementTOTPAttempts' SELECT ... FOR UPDATE locks and immediately releases per autocommit statement (no serialization → lost-update races on the counter), and ReplaceRecoveryCodes' DELETE+INSERTs auto-commit individually (a mid-loop failure wipes the code set — the very hazard the transaction is documented to prevent). Not reachable with *pgxpool.Pool/pgx.Tx (both have Begin), so only a custom handle degrades.

### Passkey / WebAuthn (`passkey/`)

- **NewService does not reject an empty RPID** — `passkey/service.go:123`  
  NewService validates the store, cookie key, and challenge store, but never checks RPID. go-webauthn's Config.validate() (types.go:141) only validates RPID when it is non-empty, so RPID="" with valid RPOrigins passes webauthn.New. Every subsequent ceremony then compares the authenticator's rpIdHash against SHA256(""), which never matches a real domain, so all logins/registrations fail. This fails closed (no auth bypass) but is a silent misconfiguration a fail-fast constructor should catch, matching the package's stated secure-by-default/fail-fast contract.
- **A verified login can be turned into a 404 if the stored credential cannot be re-found** — `passkey/service.go:265`  
  After go-webauthn verifies the assertion, FinishLogin/FinishDiscoverableLogin call findStoredCredential then applyLoginMetadata. If findStoredCredential returns nil (existing==nil) — e.g. the denormalized Credential.ID diverges from the ID inside the Data JSON that go-webauthn returned, or a concurrent delete — applyLoginMetadata still calls UpdateCredential, which returns ErrCredentialNotFound, so a cryptographically successful login is reported as 404 credential_not_found. Not reachable in the normal path (IDs are written together at registration), but there is no guard and the mismatch would convert a valid auth into a confusing client error.
- **Orphaned challenge entry when storeSession fails after recordChallenge** — `passkey/handlers.go:141`  
  In all Begin handlers recordChallenge (Put) runs before storeSession. If storeSession fails (cookieKeyFor returns a 500 because a per-tenant WithTenantCookieKeys resolver errors or yields a short key), the challenge is already recorded but no usable cookie is issued, leaving an entry that can never be consumed. It is pruned lazily at its TTL and cannot be exploited (no cookie means no Finish), so this is only a minor resource leak, not a security hole.

### Tokens — JWT (`tokens/jwt/`, `basic`, `memory`)

- **Rotate consumes the refresh token before the replacement is durably issued (non-atomic)** — `tokens/jwt/issuer.go:794`  
  ConsumeRefreshToken (line 794) marks the presented token single-use, then issuePair (line 830 -> SaveRefreshToken line 481, or the signing step line 456) mints and persists the successor. If that successor step fails transiently (store error / signing error), the old token is already consumed but no replacement exists. The client's retry with the same (now consumed) token yields ErrRefreshConcurrent within the 10s grace, and AFTER the grace window it is treated as theft and RevokeFamily logs the user out of every session in the family. A single transient DB blip during rotation can therefore escalate to a full family logout ~10s later. Rotation is not transactional across consume+save, so the fix would be to order issuance-before-consume or make the pair atomic in the store.
- **CachingKeyStore grows without bound (no eviction cap / LRU)** — `tokens/jwt/keycache.go:128`  
  entries are only removed by lookup-when-expired (line 109) or explicit Invalidate/InvalidateAll. A tenant cached once and never resolved again keeps its (stale-past-TTL) cachedKeyset in the map forever. In a deployment with a large, churning tenant population this is an unbounded memory footprint holding key material; there is no max-size or periodic sweep. Consider a bounded cache or a background reaper.
- **Config doc claims a static-keyset fallback for unknown tenants that the Service does not implement** — `tokens/jwt/issuer.go:104`  
  Config.KeyStore's doc (lines 103-108) states 'The static keyset still serves the single-tenant partition ("") and is the fallback when a tenant is unknown to the KeyStore.' But when keyStore != nil, resolveSigningKey (keystore.go:28) always delegates to keyStore.ActiveSigningKey (including tenant "") and tenantKeyFunc (keystore.go:45) always uses keyStore.VerificationKeys — the static s.active/s.verifySigners are never consulted for signing/verifying, only for PublicJWKS. The behavior fails closed (unknown tenant -> KeyStore error -> issue fails / token rejected) so it is not a security hole, but an operator relying on the documented fallback will be surprised, and the required-but-unused static SecretKey is a usability wart.
- **Reuse-grace window is measured with wall-clock time.Since, bypassing the injected Clock** — `tokens/jwt/issuer.go:755`  
  Every other time comparison in the Service uses the injected s.now (exp/nbf via WithTimeFunc, refresh expiry line 714/772, API-key expiry line 970), but the reuse-grace decision uses time.Since(*rt.ConsumedAt) (real wall clock). This is self-consistent for the memory store (which stamps ConsumedAt with time.Now().UTC()), but for a store whose ConsumedAt comes from a different clock (e.g. a DB server skewed from the app, or an app running a deliberately skewed Config.Clock), the grace window is computed across two different time sources and can misclassify benign concurrency as theft (family revocation) or vice-versa.

### Passwords (`passwords/`: argon2, breach, policy)

- **DefaultPolicy performs no breach/denylist screening** — `passwords/policy/default.go:35`  
  DefaultPolicy enforces only length + character-class composition. A weak-but-compliant secret like "Password1!" or "Qwerty123!" passes Verify. An operator who wires DefaultPolicy (the older/complexity-style policy) into identity.NewService gets zero compromised-credential protection, unlike PassphrasePolicy which supports a denylist and BreachChecker. This is intentional (two policies are offered) and documented, but it is a real deployment foot-gun: complexity rules are known to be weak, and nothing in DefaultPolicy nudges the operator toward breach screening.
- **offline WithThreshold silently ignored for bare-hash lines** — `passwords/breach/offline/offline.go:67`  
  LoadHashes only applies the count threshold when a line contains ":"; a bare 40-char hash line is always loaded as breached (documented at WithThreshold, offline.go:38). If an operator feeds a mixed corpus and sets WithThreshold(N) expecting all sub-N entries to be dropped, any bare-hash rows are still treated as breached regardless of N. Benign for a pure HIBP-count dump, but a mismatch between operator intent and behavior for custom blocklists.
- **DefaultPolicy MaxLength not coordinated with hasher MaxPasswordLength** — `passwords/policy/default.go:43`  
  A custom DefaultPolicy with MaxLength=0 (no max) or a large value accepts a multi-thousand-rune password that then fails at hash time with ErrPasswordTooLong (hasher caps at 1024 bytes). PassphrasePolicy's default (256 runes = at most 1024 bytes) is coincidentally exactly aligned with MaxPasswordLength, but DefaultPolicy has no such coordination, so a registration can pass policy and fail hashing. Not a security hole (the hasher guards the DoS), but produces a confusing late error rather than a clean policy rejection.

### Facade & internal (`actor.go`, `doc.go`, `internal/`)

- **OriginAllowed permissive default is a footgun and is dead code in production** — `internal/httputil/httputil.go:60`  
  OriginAllowed returns true unconditionally when trustedOrigins is empty (line 61-63). No production caller uses it: identity/handlers.go:500 and tokens/handlers.go re-implement a strict copy precisely BECAUSE OriginAllowed's empty-allowlist default is permissive (see the explicit comment at identity/handlers.go:499). The function is referenced only by its own test. A future maintainer who reaches for the shared helper named OriginAllowed for CSRF protection, and constructs it with an empty/nil allowlist (e.g. before config is populated), gets accept-all with no compile-time or runtime signal. Either delete it or invert the default to fail-closed. Not confirmed because there is no current call path that misbehaves.
- **doctest symbolExists can report a nonexistent symbol as present (false green)** — `internal/doctest/main.go:245`  
  symbolExists keys off substrings in `go doc` output and returns true whenever output is non-empty and none of the known error phrases match (line 249-258). If `go doc importPath symbol` fails for a reason whose message differs from the hard-coded phrases (a future Go wording change, a toolchain/module-download error printed to stderr and captured by CombinedOutput), the non-empty error text is treated as a successful resolution, so genuine doc drift passes CI silently — the exact failure this tool exists to catch. Low impact (CI-only guard tool), not reproduced against the current toolchain.
- **doctest silently skips files that fail to parse** — `internal/doctest/main.go:202`  
  goPackageDocRefs returns nil on any ParseFile error (line 202-204, the nilerr the brief flagged). A .go file whose package clause/doc comment cannot be parsed is dropped from the drift scan with no diagnostic, so drift in that file's package doc goes unnoticed. The behavior is deliberate (comment says so) and PackageClauseOnly rarely errors, so this is a robustness risk, not a confirmed miss; consider emitting a warning under -v.

### Supporting (`event`, `ratelimit`, `janitor`, `health`, `webapp`, `examples`, `adapters/otel`)

- **Janitor silently swallows a panicking cleanup fn, re-introducing the memory-leak DoS the package exists to prevent** — `janitor/janitor.go:104`  
  The tick loop wraps fn() in `defer func(){ _ = recover() }()`, discarding the recovered value with no log — unlike event.safeEmit (event.go:119-125) which logs. If a caller's cleanup fn panics on every tick (e.g. a store bug or a nil map deref inside DeleteExpired), eviction never runs, the in-memory maps grow without bound, and there is zero signal that the janitor is broken. The package doc (janitor.go:14-16) explicitly frames unbounded growth as 'a trivial denial-of-service vector', so a silently-dead janitor recreates exactly that with no observability. Not CONFIRMED because it requires a caller-supplied fn that panics; recommend logging the recovered value via slog and documenting the recover in Start's doc.
- **webapp accepts TrustedOrigins together with InsecureNoOriginCheck and silently runs insecure** — `webapp/webapp.go:169`  
  The build guard (line 122) only rejects EMPTY TrustedOrigins without the insecure opt-in. If a consumer sets both TrustedOrigins (lines 169-172 wire WithTrustedOrigins) AND InsecureNoOriginCheck=true (lines 173-178 wire WithInsecureNoOriginCheck last), the origin allowlist they provided is silently overridden and every origin is accepted. A user who supplied origins reasonably expects them enforced; the combination should arguably error at build time rather than silently disabling CSRF. Not CONFIRMED as a vuln because InsecureNoOriginCheck is a documented explicit opt-out, but it is a real footgun with no diagnostic.

---

## 4. Nits (advisory — style, comments, typos, modern Go, coverage)

### OAuth / OIDC (`oauth/`, `oauth/providers/`)

- `oauth/oidc.go:195` **[error-handling]** fmt.Errorf("%w: %v", ErrIDTokenInvalid, err) wraps the sentinel via %w but flattens the underlying jwt error with %v, so it is not unwrappable and mixes styles. House style is errors.Join(ErrIDTokenInvalid, err).
  - *Fix:* return nil, errors.Join(ErrIDTokenInvalid, err)
- `oauth/oidc.go:328` **[error-handling]** Same %w+%v pattern (also :333, :341, :413, :492, :517): underlying error flattened to %v, non-unwrappable, inconsistent with the errors.Join house style.
  - *Fix:* errors.Join(errors.New("building JWKS request"), err) (and analogously for the others)
- `oauth/providers/oidc.go:143` **[modern-go]** fmt.Errorf with a constant format string and no arguments (perfsprint) — should be errors.New. Same at oidc.go:141 for the issuer-match message.
  - *Fix:* return nil, errors.New("oidc discovery: document missing authorization_endpoint or token_endpoint")
- `oauth/provider.go:241` **[error-handling]** Exchange/GetJSON use fmt.Errorf("%w: %v", ErrExchangeFailed/ErrUserInfoFailed, err) (also :251, :284, :292): underlying transport/decode error flattened to %v. Prefer errors.Join to match house style and keep the cause unwrappable.
  - *Fix:* errors.Join(ErrExchangeFailed, err)
- `oauth/oidc.go:274` **[comment]** The jwksCache doc comment's first two lines (274-275) are duplicated verbatim at 276-277 (dupword-style duplication).
  - *Fix:* Delete the duplicated lines 274-275, keeping the single doc block starting at 276.
- `oauth/provider.go:123` **[comment]** Stale/misleading doc: New's comment says an invalid endpoint configErr is 'surfaced eagerly by AuthCodeURL/Exchange', and WithOIDC's comment (provider.go:76-84) similarly implies AuthCodeURL surfaces it — but AuthCodeURL (provider.go:160-183) never inspects p.configErr; only Exchange (provider.go:215) does. A misconfigured provider still builds a (malformed) auth URL and redirects; the error only surfaces at Exchange.
  - *Fix:* Either make AuthCodeURL return/emit configErr, or correct the comments to say the deferred error is surfaced by Exchange only.
- `oauth/oidc.go:238` **[dead-code]** audienceValues has a case []string that jwt.MapClaims never produces (JSON arrays decode to []any), so it is unreachable for the real call site at oidc.go:210. Harmless but dead.
  - *Fix:* Drop the []string case, or add a comment noting it exists only for direct callers.
- `oauth/providers/oidc_providers_test.go:80` **[test-coverage]** No test constructs Google (or any issuer whose jwks_uri host differs from the issuer host) with oauth.WithOIDC and asserts verification succeeds. TestOIDCConfig_ExplicitJWKSHostMatchAccepted only covers same-host; Cognito's test builds JWKS as issuer+suffix (same host). This gap is exactly why the confirmed Google breakage ships unnoticed.
  - *Fix:* Add a test that builds a provider with a cross-host jwks_uri (mirroring Google's topology) through WithOIDC and asserts a valid id_token verifies (which currently fails), pinning the intended cross-host behaviour.
- `oauth/oidc.go:57` **[comment]** OIDCConfig doc says Exchange 'validates ... plus the iss / aud / exp / iat and nonce claims' but the verifier also relies on jwt defaults for nbf and enforces azp (OIDC 3.1.3.7) — the doc omits azp/nbf. Minor accuracy gap on an exported type.
  - *Fix:* Mention azp (authorized-party) validation in the OIDCConfig doc comment.

### Tokens — core (`tokens/`: handlers, middleware, cookies)

- `tokens/middleware.go:470` **[comment]** WithGate's doc says the predicate 'runs after all built-in gates (kind, scopes, AMR, auth-age, password-change)', but kindSatisfied is enforced in RequireAuth/ContextMiddleware's onAuth callback (middleware.go:179, context.go:62) AFTER cfg.gate runs inside serveAuthenticated (middleware.go:234/288). So the app gate actually runs before the kind gate, and runs even for principals the kind gate will reject.
  - *Fix:* Correct the doc to list kind as running after the app gate, or move the kindSatisfied check into serveAuthenticated ahead of cfg.gate so the stated ordering holds.
- `tokens/middleware.go:312` **[error-handling]** extractAccessToken does strings.Split(authHeader, " ") and requires len(parts)==2, so a header with extra internal whitespace like 'Bearer  <token>' (two spaces) or trailing space is silently treated as no token.
  - *Fix:* Use strings.Fields(authHeader) (len==2) or strings.SplitN with a trimmed token to tolerate benign whitespace.
- `tokens/cookies.go:175` **[edge-case]** SetRefresh persistent branch computes maxAge := max(int(time.Until(expiresAt).Seconds()), 1); when expiresAt is already in the past this emits a 1-second PERSISTENT cookie (with Expires in the past) rather than declining persistence, which is a confusing artifact for an expired token.
  - *Fix:* If time.Until(expiresAt) <= 0, fall back to writing a session cookie (skip MaxAge/Expires) instead of clamping to 1s.
- `tokens/context.go:119` **[lint]** dupword lint fires on the repeated 'string' tokens in the passkey example signature '(uuid.UUID, string, string, string, bool)' embedded in the doc comment; it is a false positive from a code sample, not prose.
  - *Fix:* Ignore via linter config, or reword the example to avoid three consecutive identical types (e.g. add a short //nolint or annotate the params).
- `tokens/redact.go:42` **[consistency]** APIKey.String()/LogValue() render Hash (the at-rest lookup key / stored credential) in cleartext logs. It is a deliberate documented choice ('prefix and hash are not secret'), but the refresh-token hash is the exact value stored server-side for lookup, so logs become sufficient to correlate/enumerate stored records.
  - *Fix:* Consider truncating the hash (e.g. first 8 hex chars) in log/string output, or document explicitly in SECURITY.md that full hashes may appear in logs; low priority.

### Identity (`identity/`)

- `identity/service.go:933` **[correctness]** VerifyEmail uses `time.Now()` directly for EmailVerifiedAt instead of the injected `s.now()` clock. Every other Confirm*/Reset flow (ConfirmEmailChange:849, ConfirmPhoneVerification:1145, ConfirmRecoveryEmail:1226) uses s.now(). This makes VerifyEmail's timestamp non-deterministic under WithClock and inconsistent with the rest of the service.
  - *Fix:* Change `now := time.Now()` to `now := s.now()`.
- `identity/identity.go:45` **[comment]** The doc comment `// Identity represents an authentication method linked to a User.` is duplicated on lines 44 and 45 (dupword/copy-paste).
  - *Fix:* Delete the duplicate line 45.
- `identity/handlers.go:1323` **[naming]** RequestPasswordResetViaRecoveryHandler delivers a PASSWORD-RESET token through the SMSSender.PhoneVerification callback and a PhoneVerificationSMS struct. The application receiving that callback cannot tell a reset token from a phone-verification code, and the struct name mislabels the payload.
  - *Fix:* Either add a dedicated PasswordResetSMS callback/struct to SMSSender, or document explicitly on SMSSender.PhoneVerification that it is reused to carry recovery-reset tokens.
- `identity/servicetest/contract.go:125` **[test-coverage]** MockService.AuthenticateFunc drops the `rc ...event.RequestContext` variadic (the wrapper at :129 discards it), so any handler/service test using this mock cannot assert that the request context (client IP / UA) is forwarded into login.* events.
  - *Fix:* Give AuthenticateFunc the `rc ...event.RequestContext` parameter and forward it, so RequestContext propagation is testable through the mock.
- `identity/service.go:1215` **[test-coverage]** No test covers the ConfirmRecoveryEmail-equals-new-primary independence edge case, nor the re-lockout-after-expiry event behavior (the confirmed finding). events_test.go asserts AccountLocked fires once on the first crossing but never re-authenticates after a lock expires.
  - *Fix:* Add a test that authenticates past a threshold, advances the clock past LockedUntil, fails once more, and asserts a second AccountLocked event is (should be) emitted.
- `identity/service.go:1339` **[error-handling]** PasswordChangeRequired is an exported Service method with no doc comment (unlike its siblings). Minor house-style gap.
  - *Fix:* Add a one-line doc comment describing the enumeration-safe/false-on-OAuth-only behavior.

### Sessions (`sessions/`)

- `sessions/service.go:94` **[error-handling]** generateToken uses fmt.Errorf("...: %w", err); house style (CLAUDE.md) is errors.Join(errors.New("failed to generate random session token"), err).
  - *Fix:* return "", errors.Join(errors.New("sessions: failed to generate random session token"), err)
- `sessions/service.go:262` **[correctness]** WithMaxLifetime doc says 'If you call both WithMaxLifetime and WithNoMaxLifetime the last option wins' — this is false for the WithNoMaxLifetime-then-WithMaxLifetime order (see confirmed finding). Fix the code so WithMaxLifetime(d>0) also clears s.noMaxLifetime, then the comment becomes accurate.
  - *Fix:* In WithMaxLifetime, when d>0 also set s.noMaxLifetime=false so a later WithMaxLifetime genuinely re-enables the cap.
- `sessions/service.go:114` **[consistency]** CreateSession sets ExpiresAt = now+duration with no clamp to the absolute deadline, unlike Touch/Rotate/BindUser which clampExpiry. A duration greater than maxLifetime produces an ExpiresAt beyond the cap. Harmless (ValidateSession still enforces the cap) but inconsistent with the slide paths.
  - *Fix:* session.ExpiresAt = s.clampExpiry(session, now.Add(duration)) after CreatedAt is set.
- `sessions/service.go:99` **[input-validation]** CreateSession does not reject a non-positive duration; duration<=0 mints an already-expired session (TestTouchAndRotate_RejectExpiredSession relies on this). A guard or doc note would prevent accidental zero-duration sessions.
  - *Fix:* Document that duration must be >0, or return an error for duration<=0.
- `sessions/lifetime_test.go:125` **[test-coverage]** No test exercises the WithNoMaxLifetime()+WithMaxLifetime() combination in either order; the confirmed cap-disable bug slips through. Add a test asserting NewService(store, WithNoMaxLifetime(), WithMaxLifetime(1h)) still enforces a 1h absolute cap.
  - *Fix:* Add TestMaxLifetime_NoThenMaxReenablesCap covering both orderings.
- `sessions/service_test.go:16` **[test-coverage]** No test covers WithClock(nil) falling back to time.Now (the guard at service.go:77-79) nor a lowercase 'bearer ' Authorization prefix (CutPrefix is case-sensitive, middleware.go:57).
  - *Fix:* Add a WithClock(nil) construction test and a lowercase-Bearer 401 test.
- `sessions/memory/store.go:22` **[efficiency]** FindSessionByHash takes the full write Lock (needed only for the opportunistic eviction). Reads on live sessions could use RLock with a deferred upgrade, but the current code is simple and correct; low priority.
  - *Fix:* Optional: RLock fast-path, upgrade to Lock only when eviction is needed.

### MFA & OTP (`mfa/`, `otp/`)

- `otp/memory/store.go:34` **[dupword]** The doc comment line 'Store is an in-memory implementation of otp.Store.' is duplicated verbatim on lines 33 and 34 (copy-paste). This is the dupword-class issue flagged in the brief for this package.
  - *Fix:* Delete the duplicated line 34.
- `mfa/service.go:310` **[comment]** The sentence 'Reserve a slot before the lookup/compare so a locked factor cannot be brute-forced through the recovery path either.' appears twice — once at lines 303-304 and again at lines 310-311 inside the `case gated:` block.
  - *Fix:* Remove the redundant repetition at lines 310-311.
- `mfa/service.go:100` **[doc-mismatch]** WithLockoutDuration's doc (lines 100-107) states 'Once the window elapses, the next attempt is treated as a fresh budget,' but IncrementTOTPAttempts only applies decay when FailedAttempts >= maxAttempts (mfa/memory/store.go:92-106). A partial counter below the limit (e.g. 4 of 5 fails) never ages out, so a user returning after the window still has only 1 attempt left. Behavior is more conservative than documented, not a security bug.
  - *Fix:* Reword the doc to say decay applies only once the factor is locked (>= maxAttempts), matching the TOTPStore.IncrementTOTPAttempts contract and the implementation.
- `mfa/memory/store.go:137` **[consistency]** ConsumeRecoveryCode compares stored vs submitted code hashes with plain `==` (c.CodeHash == codeHash), whereas otp/code.go and mfa/totp.go use subtle.ConstantTimeCompare. Both sides are server-side SHA-256 hashes of high-entropy (80-bit) codes, so the timing leak is not exploitable (SHA-256 preimage resistance), but it is inconsistent with the constant-time discipline used everywhere else in the unit.
  - *Fix:* Optional: use subtle.ConstantTimeCompare for the hash equality for consistency, or document why the hashed-lookup path is exempt.
- `otp/code.go:13` **[comment]** generateCode's comment says it uses 'rejection-free big.Int sampling.' crypto/rand.Int is NOT rejection-free — it performs internal rejection sampling to avoid modulo bias. The conclusion (no modulo bias) is correct but the mechanism description is wrong.
  - *Fix:* Reword to 'uniform crypto/rand.Int sampling (rejection sampling internally), so there is no modulo bias.'
- `mfa/service_test.go:1` **[test-coverage]** No test appears to cover VerifyRecoveryCode being rejected with ErrTooManyAttempts while the TOTP factor is locked (the risk noted above). Given it is a deliberate and security-relevant behavior, a regression test would pin the contract that recovery codes share and are blocked by the TOTP lockout.
  - *Fix:* Add a test: enroll+confirm, exhaust maxAttempts with wrong TOTP codes, then assert a KNOWN-valid recovery code returns ErrTooManyAttempts (not success) until decay/UnlockMFA.
- `otp/handlers_test.go:1` **[test-coverage]** issue_delivery_bounds_test.go covers the delivery fan-out cap, but there is no test asserting the response-latency uniformity property the IssueHandler doc claims (the confirmed timing-oracle finding). A test that measures/asserts svc.Issue is not on the response path (or documents that it is) would prevent silent regressions of the enumeration guarantee.
  - *Fix:* Either move svc.Issue off the response path (dispatch it alongside delivery) and add a test, or update the doc comment to drop the 'leaks no account-existence signal' claim for DB-backed stores.

### Keystore (`keystore/`)

- `keystore/manager.go:333` **[unparam]** emit's reason parameter is dead: all four call sites (lines 133, 185, 214, 233) pass "", so event.Event.Reason is never populated for any keystore lifecycle event. Either drop the reason parameter (unparam) or populate a meaningful machine reason (e.g. "revoked"/"deleted") to make the emitted events more useful for auditing.
- `keystore/resolve.go:37` **[consistency]** Lazy provisioning is honored only by ActiveSigningKey (resolve.go:17) but not by VerificationKeys (:37), JWKS (via VerificationKeys), NotAfter (:92) or NeedsRenewal (:103). With WithLazyProvisioning enabled, ActiveSigningKey auto-creates an unknown tenant while a concurrent/first JWKS or NeedsRenewal call on the same unknown tenant returns ErrTenantNotFound. Document that only the sign path auto-provisions, or route the read paths through the same lazy hook for consistent behavior.
- `keystore/manager.go:209` **[stale-comment]** RevokeTenantKeys doc says '(re-provision or renew to restore signing)', but re-provision is a no-op after revoke (see confirmed finding). Correct the comment to say renewal (RenewSigningKey) restores signing; re-provision does not.
- `keystore/jwks_test.go:12` **[test-coverage]** JWKS tests cover only RSA (N/E) and HS256 (oct metadata). There is no test asserting the EC (Kty=EC, Crv, X, Y from pub.Bytes() SEC1 split at jwks.go:107-116) or EdDSA (Kty=OKP, Crv=Ed25519, X at :117-126) public-parameter output. Add a round-trip test that decodes the published X/Y/Crv and rebuilds the public key so a coordinate-slicing regression is caught.
- `keystore/keystoretest/contract.go:209` **[test-coverage]** testRevokeKeys asserts no active/verification keys remain after revoke but never re-provisions or renews afterward. A follow-up assertion (renew restores an active key; re-provision behavior is defined) would have caught the confirmed re-provision-after-revoke no-op. Add it to the shared contract so every backend is checked.
- `keystore/jwtadapter.go:98` **[test-coverage]** The ES256/384/512 curve-vs-stored-alg cross-check (rejecting e.g. Alg "ES256" on a P-384 key) is a key-confusion guard with no test. Add a test that constructs a SigningKey with a mismatched Alg/curve and asserts signerFor returns the 'does not match its curve-derived alg' error.
- `keystore/resolve.go:73` **[test-coverage]** No test exercises openKey's error path (a stored Secret that is not valid KEK ciphertext, or sealed under a different KEK) through ActiveSigningKey/VerificationKeys to confirm ErrCiphertextCorrupt propagates rather than a panic or empty key. KEK.Open is unit-tested directly but not via the Manager resolve path.

### Adapter — Postgres (`adapters/pgx/`)

- `adapters/pgx/identity/migrations/001_create_tables.sql:11` **[migration-idempotency]** idx_users_email_tenant (line 11) and idx_identities_provider_tenant (line 25) use bare CREATE UNIQUE INDEX with no IF NOT EXISTS, violating the pgxmigrate authoring contract (every file MUST be idempotent) and diverging from every other migration in the module, all of which use CREATE [UNIQUE] INDEX IF NOT EXISTS. Harmless on a fresh DB (version row commits atomically) but fails permanently if the table/index pre-existed outside migration tracking.
  - *Fix:* Add IF NOT EXISTS to both CREATE UNIQUE INDEX statements.
- `adapters/pgx/identity/store.go:1` **[doc-comment]** Missing package doc comment (revive). Same for sessions/store.go:1, oauth/store.go:1, tokens/store.go:1 — mfa/otp/passkey/keystore have one.
  - *Fix:* Add a `// Package pgx ...` doc comment to each of these four files' package clause.
- `adapters/pgx/identity/store.go:66` **[doc-comment]** Numerous exported methods lack doc comments: identity CreateUser:66, FindUserByID:87, FindUserByEmail:107, UpdateUser:127, AddIdentity:231, FindIdentitiesByUserID:275, FindIdentityByProvider:312, FindUserByPhone:516; mfa SaveTOTP:59, GetTOTP:94, DeleteTOTP:129, MarkTOTPUsed:134, IncrementTOTPAttempts:147, ReplaceRecoveryCodes:203, ConsumeRecoveryCode:243, DeleteRecoveryCodes:285, ResetTOTPAttempts:300; otp SaveOTP:47, GetOTP:69, IncrementOTPAttempts:86, ConsumeOTP:103, DeleteOTP:114.
  - *Fix:* Add a one-line doc comment to each exported method (they implement store interfaces but are still exported symbols).
- `adapters/pgx/tokens/store.go:241` **[dead-code]** FindAPIKeyByHash scans the user_id column into &key.Claims.Subject (line 241), then json.Unmarshal(claimsJSON, &key.Claims) at line 254 overwrites the entire Claims struct including Subject, making the scan into Subject dead. Same pattern in ListAPIKeysByCreator (scan at line 332, unmarshal at line 339).
  - *Fix:* Scan user_id into a throwaway (or drop it from the SELECT), or move the json.Unmarshal before re-applying the DB Subject if the column is meant to be authoritative.
- `adapters/pgx/keystore/store.go:109` **[efficiency]** ActiveSigningKey (109), VerificationKeys (138) and RevokeTenantKeys (211) each issue a separate TenantExists round-trip before the main query solely to distinguish ErrTenantNotFound from ErrNoActiveKey/empty, doubling DB round-trips on the hot verification path.
  - *Fix:* Fold existence detection into the main query (e.g. left-join a per-tenant marker, or return ErrTenantNotFound only when the tenant truly has zero rows) to save a round-trip.
- `adapters/pgx/mfa/store.go:182` **[duplication]** The anonymous `interface{ Begin(context.Context) (pgx.Tx, error) }` assertion is repeated in IncrementTOTPAttempts:182, ReplaceRecoveryCodes:226 and ConsumeRecoveryCode:268; keystore already defines a named txBeginner for exactly this.
  - *Fix:* Extract a package-level named interface (mirroring keystore.txBeginner) and assert against it in all three sites.
- `adapters/pgx/internal/pgxmigrate/pgxmigrate.go:85` **[robustness]** Run appends `\nINSERT INTO schema_migrations ...` directly after the file body; if a migration file's final statement lacks a trailing semicolon the INSERT concatenates onto it and produces a syntax error. All current files end with ';', so this is latent, but the contract relies on an unstated 'end every file with ;' rule.
  - *Fix:* Prepend a defensive separator, e.g. `string(content) + ";\n" + INSERT...`, or document the trailing-semicolon requirement in the package contract.
- `adapters/pgx/oauth/cache_internal_test.go:72` **[test-coverage]** Cache tests cover the happy path and invalidation but not the failure the confirmed finding describes: a KEK.Open error on a cache HIT. No test asserts that a cached provider survives a transient decrypt failure (currently it does not).
  - *Fix:* Add a test with a KEK whose Open fails on the 2nd call and assert GetProvider still returns the cached provider (after the suggested reorder).
- `adapters/pgx/keystore/store_test.go:1` **[test-coverage]** No coverage for the non-txBeginner CreateTenant fallback (store.go:58-61) nor the mfa non-beginner fallbacks (mfa/store.go:185/229/271); their degraded semantics are untested, so a regression that made these the default path would pass CI.
  - *Fix:* Add a DBQuerier stub without Begin and assert the fallback still behaves (or is intentionally rejected).

### Passkey / WebAuthn (`passkey/`)

- `passkey/handlers.go:401` **[modern-go]** consumeChallenge takes parameters in the order (w http.ResponseWriter, ctx context.Context, ...). Go convention (and lint) is that context.Context is the first parameter. Reorder to consumeChallenge(ctx, w, tenant, session) for consistency with the rest of the codebase.
  - *Fix:* func (cfg handlerConfig) consumeChallenge(ctx context.Context, w http.ResponseWriter, tenant string, session webauthn.SessionData) bool
- `passkey/attestation_test.go:76` **[test-coverage]** Attestation rejection is only asserted at the service level (ErrAttestationRejected). There is no handler-level test asserting the HTTP status FinishRegistrationHandler returns for a policy-rejected registration, which is why the 500-instead-of-4xx mapping (confirmed finding) went unnoticed.
  - *Fix:* Add a FinishRegistrationHandler test with a deny-list AAGUID asserting the intended 4xx status once fail() maps ErrAttestationRejected.
- `passkey/service.go:517` **[naming]** handle := userID followed by handle[:] is an unnecessary copy of the uuid array; userID[:] slices the array directly.
  - *Fix:* Use protocol.URLEncodedBase64(userID[:]) and drop the handle local.
- `passkey/handlers.go:511` **[simplification]** cred is captured then discarded via `_ = cred`. Discard it directly at the call to avoid the dead assignment.
  - *Fix:* _, uid, err := svc.FinishDiscoverableLogin(r.Context(), tenant, session, r)
- `passkey/service.go:221` **[consistency]** FinishRegistration returns the *Credential produced by toStored, whose TenantID is empty (""). SaveCredential only sets TenantID on its internal clone, not on the caller's pointer, so the returned record's TenantID does not reflect the tenant it was saved under. A caller reading stored.TenantID sees an empty string.
  - *Fix:* Set stored.TenantID = tenantID before returning (or after SaveCredential) so the returned record is self-consistent.
- `passkey/handlers.go:123` **[error-handling]** WithCookieKey accepts any key including a short or empty one; the too-short check is deferred to cookieKeyFor at request time (fails closed with 500). This is safe but a construction-time foot-gun; consider documenting that a short per-handler key silently disables the handler with a 500.
  - *Fix:* Document the >= MinCookieKeyLength requirement on WithCookieKey (already covered in the doc comment) — optionally log at first use.

### Tokens — JWT (`tokens/jwt/`, `basic`, `memory`)

- `tokens/jwt/issuer.go:621` **[comment]** Stale doc: verifyAccessToken's comment says it is 'the shared core used by the public VerifyAccessToken (single-tenant) and VerifyAccessTokenForTenant', but no exported VerifyAccessToken exists — the only public entry point is VerifyAccessTokenForTenant.
  - *Fix:* Drop the reference to the non-existent 'public VerifyAccessToken (single-tenant)'; say it is the shared core behind VerifyAccessTokenForTenant.
- `tokens/jwt/issuer.go:835` **[comment]** Stale doc: VerifyAccessTokenForTenant's comment says 'It first runs the full ... validation of VerifyAccessToken', referencing a method that no longer exists.
  - *Fix:* Reference verifyAccessToken (the unexported core) instead of VerifyAccessToken.
- `tokens/jwt/issuer.go:663` **[error-handling]** fmt.Errorf("%w: %v", tokens.ErrInvalidToken, err) renders the underlying parser error with %v, so it is not joinable/matchable (only the sentinel is). Against the project's errors.Join house style.
  - *Fix:* errors.Join(tokens.ErrInvalidToken, err) so callers can errors.Is/As the underlying cause too.
- `tokens/jwt/issuer.go:757` **[error-handling]** fmt.Errorf("%w: family revocation failed: %v", tokens.ErrRefreshTokenReused, rerr) swallows rerr with %v (only the sentinel is matchable). The RevokeFamily failure cause is lost to callers.
  - *Fix:* errors.Join(tokens.ErrRefreshTokenReused, errors.New("family revocation failed"), rerr).
- `tokens/jwt/issuer.go:458` **[house-style]** fmt.Errorf("...: %w", err) wrapping is used at several exported-path return sites (issuer.go:458 sign, :464 refresh gen, :521 apikey gen; keystore.go:34, :49, :61) whereas CLAUDE.md mandates errors.Join instead of %w.
  - *Fix:* Convert %w wraps to errors.Join(errors.New("..."), err) for consistency with the rest of the codebase.
- `tokens/jwt/issuer.go:458` **[error-handling]** Exported issue paths return ad-hoc inline errors (fmt.Errorf("failed to sign token"), fmt.Errorf("failed to generate refresh token"), fmt.Errorf("failed to generate api key")) rather than declared sentinels, so callers cannot match them; contrast ErrPATSubjectMismatch which is a proper sentinel.
  - *Fix:* Introduce sentinels (e.g. ErrSignFailed, ErrTokenGen) and join the cause, so callers can distinguish signing/entropy failures.
- `tokens/memory/store.go:192` **[godot]** Comment '// Verify interface compliance' has no trailing period (godot) and is awkwardly placed mid-file between RevokeAPIKey and the other methods rather than near the type.
  - *Fix:* End with a period and move the var _ tokens.Store assertion next to the Store type declaration.
- `tokens/jwt/issuer.go:538` **[robustness]** IssueAPIKey's else branch treats ANY non-KeyTypeService value (including an empty/invalid KeyType) as a PAT — enforcing the PAT subject rules and pinning Subject=createdBy for an unclassified type. ActorFromAPIKey later maps the unknown type to egauth.User, so the stored Type and the derived Kind disagree.
  - *Fix:* Validate keyType is one of KeyTypePAT/KeyTypeService up front and reject unknown values, or document that non-Service is deliberately coerced to PAT semantics.
- `tokens/jwt/issuer.go:150` **[consistency]** Config.Validate flags a weak SecretKey unconditionally and never consults InsecureAllowWeakKey, while New honors it — so a valid test config (InsecureAllowWeakKey + short key) passes New but fails Validate. The interaction is undocumented on Validate.
  - *Fix:* Either skip the length check when InsecureAllowWeakKey is set, or document that Validate is intentionally stricter than New here.
- `tokens/jwt/redact.go:66` **[consistency]** Config.LogValue emits fewer fields than Config.String (String includes RefreshLength/APIKeyLength/ReuseGracePeriod and the *Set booleans; LogValue omits them), so the two redaction surfaces diverge. Both are safe, just inconsistent.
  - *Fix:* Align the two representations to emit the same non-secret field set.
- `tokens/jwt/jwks.go:39` **[test-coverage]** PublicJWKS only serves the static-path verifySigners; when a KeyStore is configured, per-tenant verification keys are never published, so an external verifier of per-tenant tokens cannot obtain keys from PublicJWKS. This limitation is stated only implicitly ('static-path') and has no test asserting the KeyStore-mode behavior.
  - *Fix:* Document the KeyStore limitation on PublicJWKS explicitly and/or add a per-tenant JWKS accessor; add a test pinning that PublicJWKS ignores KeyStore keys.
- `tokens/jwt/keystore.go:45` **[test-coverage]** No test covers the failure mode where a KeyStore-resolved active signer returns an empty KeyID: issuePair then stamps no kid, but tenantKeyFunc rejects kid-less tokens (line 52), so the service would fail to verify its own freshly issued token. issuePair does not guard against an empty KeyID from a KeyStore.
  - *Fix:* Assert (or enforce) that a KeyStore-backed active signer has a non-empty KeyID at issuance; add a regression test.

### Passwords (`passwords/`: argon2, breach, policy)

- `passwords/argon2/hasher.go:204` **[error-handling]** fmt.Errorf("%w: %v", passwords.ErrHashFailed, err) formats the crypto/rand error with %v, dropping it from the unwrap chain (errors.Is/As on the rand error fails). This is the errorlint hit flagged in the brief and deviates from the project's errors.Join house style.
  - *Fix:* return "", errors.Join(passwords.ErrHashFailed, err) (add errors import).
- `passwords/policy/default.go:78` **[comment]** Comment "// Verify interface compliance" has no trailing period (godot), and is inconsistent with passwords/policy/passphrase.go:144 which reads "// Verify interface compliance." with a period. The wording is also slightly misleading since it reads like it refers to the Verify method.
  - *Fix:* Make it "// Verify interface compliance." (or "// Compile-time interface check.") to match the sibling file.
- `passwords/breach/hibp/hibp.go:183` **[test-coverage]** scanForSuffix's malformed-count error path (strconv.Atoi failure on a "SUFFIX:notanumber" line) has no test; hibp_test.go only exercises well-formed counts.
  - *Fix:* Add a rangeServer case emitting "<suffix>:notanumber" and assert IsBreached returns an error under fail-closed.
- `passwords/breach/hibp/hibp.go:130` **[test-coverage]** The WithAddPadding(false) branch (Add-Padding header omitted) is never tested; all tests use the default (header present).
  - *Fix:* Add a test with WithAddPadding(false) asserting the handler received no Add-Padding header.
- `passwords/breach/offline/offline.go:71` **[test-coverage]** LoadHashes malformed-count path ("<40hex>:notanumber" -> error) is untested; offline_test only covers a valid count and a wrong-length hash.
  - *Fix:* Add a LoadHashes case with a non-numeric count and assert an error is returned.
- `passwords/breach/offline/offline.go:130` **[test-coverage]** normalizeHash's hex.DecodeString failure branch (a 40-char but non-hex string, e.g. 40 'G' chars) is untested; TestLoadHashes_RejectsMalformed uses a 21-char string that only hits the length!=40 branch.
  - *Fix:* Add a case with a 40-char non-hex string and assert an error.
- `passwords/hashertest/contract.go:21` **[missing-doc]** Exported method MockHasher.Hash (and MockHasher.Compare at line 28) on this public importable helper package lack doc comments; exported fields HashFunc/CompareFunc are also undocumented.
  - *Fix:* Add one-line doc comments (e.g. "// Hash delegates to HashFunc, panicking if it is unset.").
- `passwords/policy/default.go:57` **[simplification]** The strings.ContainsRune(" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", char) clause is almost entirely redundant with unicode.IsPunct(char)||unicode.IsSymbol(char); every listed rune except space is already punct or symbol, so the long literal only adds ' ' (space) as a special char.
  - *Fix:* Drop the ContainsRune literal and, if space should count, replace with an explicit char==' ' (or unicode.IsSpace) check to make the intent obvious.
- `passwords/policy/passphrase.go:47` **[test-coverage]** WithMaxLength(0) (disable the maximum) is documented but not tested; passphrase_test only exercises the default max.
  - *Fix:* Add a test with WithMaxLength(0) verifying an arbitrarily long passphrase passes the length check.

### Facade & internal (`actor.go`, `doc.go`, `internal/`)

- `actor.go:66` **[modern-go]** HasScope hand-rolls a linear scan; the go fix modernizer already flagged this.
  - *Fix:* return slices.Contains(a.Scopes, s) (import "slices"). HasAllScopes/HasAnyScope then remain as-is since they delegate to HasScope.
- `doc.go:5` **[stale-comment]** Package doc says the root "exports only Actor", but the root package also exports PrincipalKind and the User/PAT/Service constants (actor.go:11-26).
  - *Fix:* Reword to e.g. "it exports only Actor and its PrincipalKind classification" so the doc matches the actual exported surface.
- `internal/httputil/httputil.go:60` **[dead-code]** OriginAllowed has no production caller (only httputil_test.go references it); every handler family uses its own strict copy instead.
  - *Fix:* Remove OriginAllowed (and its test) or, if kept as the intended shared primitive, make production handlers call it and invert the empty-allowlist default to fail-closed.
- `internal/doctest/main.go:133` **[redundant-check]** `verbose != nil` is always true: verbose is the *bool returned by flag.Bool, which is never nil.
  - *Fix:* Drop the nil guard: `if *verbose && !seen[k] {`.
- `internal/httputil/httputil.go:16` **[error-handling]** WriteJSON discards the json.Encode error after WriteHeader has already committed the status; a mid-encode failure leaves a truncated body with a success status and no signal.
  - *Fix:* Acceptable for a best-effort writer, but consider encoding into a buffer first (or at least documenting that the error is intentionally dropped) so partial writes can't masquerade as complete responses.
- `internal/httputil/httputil.go:72` **[doc]** Fail's `status` argument is silently ignored on the redirect branch (always 303 SeeOther); only the http.Error branch honors it.
  - *Fix:* The doc comment is technically correct but the dropped-status behavior is a caller footgun; state explicitly that status is used only when failureURL is empty.
- `internal/httputil/httputil.go:13` **[test-coverage]** WriteJSON, WithErrorParam, Fail, and RedirectOrStatus have no direct unit tests (only OriginAllowed, RequestOriginHost, and ParseLimitedForm are covered in httputil_test.go).
  - *Fix:* Add table tests: WriteJSON content-type/status/body; WithErrorParam replace-vs-append and unparseable-input passthrough; Fail redirect-vs-plain branches; RedirectOrStatus empty-vs-nonempty URL.
- `internal/httputil/httputil.go:21` **[test-coverage]** WithErrorParam's documented "returned unchanged when rawURL cannot be parsed" branch (line 22-24) is untested, as is the existing-error-param replacement path.
  - *Fix:* Add cases for an unparseable rawURL and for a URL that already carries ?error= to lock in the replace-not-duplicate behavior.
- `internal/doctest/main.go:245` **[test-coverage]** symbolExists's error-phrase matching (the core of the drift check) has no unit test.
  - *Fix:* Extract the output-classification logic into a pure helper and table-test it against real `go doc` output samples (present symbol, "no symbol", "no such package", build-constraint exclusion).

### Supporting (`event`, `ratelimit`, `janitor`, `health`, `webapp`, `examples`, `adapters/otel`)

- `adapters/otel/sink.go:47` **[deprecated-api]** trace.NewNoopTracerProvider() is deprecated (confirmed in the pinned go.opentelemetry.io/otel/trace@v1.44.0/noop.go:18 — 'Deprecated: Use go.opentelemetry.io/otel/trace/noop.NewTracerProvider instead').
  - *Fix:* Import go.opentelemetry.io/otel/trace/noop and use noop.NewTracerProvider().Tracer("") for the nil-tracer fallback.
- `ratelimit/tokenbucket.go:134` **[stale-comment]** The WithMaxKeys doc (line 134) and evictOne doc (line 157) both claim 'Fully-refilled buckets are always preferred for eviction', but evictOne only samples 5 keys (lines 166-181). With more than 5 tracked keys a fully-refilled bucket outside the random sample is NOT necessarily chosen, so 'always' overpromises.
  - *Fix:* Reword to 'among a small random sample, the least-pressured (most-refilled) bucket is evicted' in both doc blocks (and the package doc at lines 20-21).
- `adapters/otel/sink.go:70` **[efficiency]** Extra Attrs are flattened with fmt.Sprintf("%v", v), collapsing every value to a string; ints/bools/durations lose their native OTel attribute type (attribute.Int, attribute.Bool, etc.), which hurts backend filtering/aggregation.
  - *Fix:* Type-switch on v (int/int64->attribute.Int64, bool->attribute.Bool, string->attribute.String, default->Sprintf) as slogSink does implicitly via slog.Any.
- `webapp/webapp.go:82` **[missing-doc]** Config.Routes is the only exported Config field without a doc comment; every other field (lines 47-81) is documented, so this is an inconsistency.
  - *Fix:* Add e.g. '// Routes overrides the default /auth/* route patterns; an empty Routes keeps the defaults.'
- `adapters/otel/go.mod:10` **[stale-dependency]** require github.com/JLugagne/egauth v0.3.0 while the core module is at v0.7.0 (masked locally by the replace at line 26). If the maintainer's release re-tidy is ever skipped, consumers resolve an old core.
  - *Fix:* Bump the require to match the current core tag during the release two-tag dance (already flagged by RELEASING.md); low priority.
- `janitor/janitor_test.go:1` **[test-coverage]** The recover path in Start (janitor.go:102-107) is never exercised: no test passes an fn that panics to prove the janitor recovers and keeps ticking. Given this is the safety net for a DoS-relevant loop, it should be covered.
  - *Fix:* Add a test with an fn that panics on the first N ticks then succeeds, asserting later ticks still run and Stop returns cleanly.
- `ratelimit/ratelimit_test.go:93` **[test-coverage]** Middleware is only tested on the retryAfter>0 path; the branch where allowed==false and retryAfter==0 (ratelimit.go:82) — which must omit the Retry-After header while still returning 429 — is untested.
  - *Fix:* Add a fake Limiter returning (false, 0) and assert 429 with no Retry-After header.
- `adapters/otel/sink_test.go:121` **[test-coverage]** TestSpanSink_ExtraAttrs only asserts key presence, not the stringified value, so the fmt.Sprintf("%v") behavior (e.g. int 3 -> "3") is unverified; there is also no contract/negative test asserting the sink emits nothing beyond Type/TenantID/UserID/Reason/Attrs/Err (the 'no secret leakage' invariant the brief calls out).
  - *Fix:* Assert attrs["egauth.attempt"]=="3" and add a test that an Event with only the documented fields produces exactly the expected attribute set.

---

## 5. Per-unit summaries

### OAuth / OIDC (`oauth/`, `oauth/providers/`)  — 1 confirmed · 2 risks · 9 nits

The OIDC id_token verifier is well hardened: alg-confusion (RS→HS/none) is blocked via WithValidMethods over an asymmetric-only allowlist, iss/aud/exp/iat are enforced, azp confused-deputy is checked, the nonce is mandatory and constant-time compared, JWKS parsing is bounded (key count, RSA modulus/exponent, EC on-curve), and SSRF is defended at dial time (DNS-rebind safe). State/PKCE/nonce generation uses crypto/rand and packState binds provider+tenant. However, the JWKS "same host as issuer" binding is stricter than the OIDC spec and is functionally incompatible with Google (issuer accounts.google.com vs jwks_uri www.googleapis.com): the shipped Google constants + WithOIDC produce a provider that can never log a user in. One medium risk (X-Forwarded-Proto trust) and several house-style/error-wrapping and doc nits round it out.

### Tokens — core (`tokens/`: handlers, middleware, cookies)  — 1 confirmed · 2 risks · 5 nits

The top-level tokens package (HTTP handlers, RequireAuth/ContextMiddleware, cookies, redaction, gates) is mature, well-documented, and heavily tested; cookie flags (__Host- prefix, HttpOnly always-on, Secure-by-default via Insecure opt-out, SameSite), the secure-by-default CSRF origin check, fail-closed tenant resolution, and the concurrent-refresh anti-lockout path are all sound and correctly covered by tests. The one substantive defect is that actorFromClaims (the documented consumer of Claims.Kind for API-key-backed JWTs) never populates Actor.KeyID and mis-populates Actor.UserID for Service/PAT principals, diverging from both the egauth.Actor field contract and ActorFromAPIKey. Remaining items are documentation/robustness nits: an incorrect gate-ordering claim in WithGate's doc, Claims.Groups/Roles being invisible on the RequireAuth path, and minor parsing/edge cases.

### Identity (`identity/`)  — 1 confirmed · 3 risks · 6 nits

The identity service is carefully built: tenant scoping is enforced on every store method, the selector/verifier token scheme uses crypto/rand + constant-time SHA-256 comparison, decoy hashing equalizes the Authenticate failure paths, and single-use tokens are consumed atomically. The 3 flagged nilerr hits (service.go:621, :1034, :1262) are NOT bugs — each is a deliberate enumeration-uniform return (`return "", nil, nil`) on the malformed-email branch, documented and mirroring the unknown-account path; they are false positives for this security model. The one real defect I could reproduce is an account-lockout audit gap: because FailedAttempts is never reset when a lock expires, every re-lockout after the first is silent (no AccountLocked event). Remaining issues are timing-asymmetry risks on the unauthenticated Request* endpoints and several nits.

### Sessions (`sessions/`)  — 1 confirmed · 5 risks · 7 nits

The sessions module is well-designed and heavily tested: 256-bit crypto/rand tokens, SHA-256-hashed at rest, compare-and-set rotation (Rotate/BindUser) that defeats fixation, a __Host- secure-default cookie, tenant-scoped store operations with fail-closed tenant resolution, and a documented absolute-lifetime cap (SEC-08). One confirmed correctness/security bug exists in option composition: WithNoMaxLifetime() followed by WithMaxLifetime(d>0) silently leaves the absolute cap DISABLED, contradicting the documented "last option wins" and dropping a security control. Secondary concerns are an audit-event gap (Rotate/BindUser/CreateSession emit nothing), non-idempotent RevokeSession, and the memory store hardcoding time.Now() instead of the service clock.

### MFA & OTP (`mfa/`, `otp/`)  — 1 confirmed · 3 risks · 7 nits

The TOTP/OTP crypto core is solid: 160-bit and 80-bit secrets from crypto/rand, uniform big.Int code sampling (no modulo bias), constant-time TOTP compare, monotonic LastUsedStep replay guard, atomic reserve-before-compare rate limiting with a well-reasoned concurrency proof in the contract suite, single-use recovery/OTP codes with hash-guarded consume, and consistent tenant scoping. No memory-safety, entropy, replay, or tenant-isolation defects were found. The one substantive issue is an account-enumeration timing differential in otp.IssueHandler that contradicts its own documented "leaks no account-existence signal" guarantee. The rest are design-tradeoff risks (recovery codes blocked while the TOTP factor is locked; event amplification under a concurrent flood) and comment/consistency nits.

### Keystore (`keystore/`)  — 1 confirmed · 3 risks · 7 nits

The keystore package is well-structured and its core crypto is sound: KEK is AES-256-GCM with per-seal random 96-bit nonces, HS256 secrets are never published in JWKS, asymmetric public-parameter extraction (RSA N/E, EC X/Y via SEC1, Ed25519 X) is correct, and the ES256/384/512 curve-vs-stored-alg cross-check in signerFor guards against key-confusion. Tenant isolation is enforced by map partitioning plus guardTenant. The one concrete defect is a lifecycle contract violation: after RevokeTenantKeys the memory store leaves an empty-but-present tenant partition, so the documented "re-provision to restore signing" recovery path is a silent no-op that leaves the tenant permanently unable to sign. Secondary concerns are the absence of any zeroization of opened plaintext key material and several test-coverage gaps (EC/EdDSA JWKS output, re-provision-after-revoke, the ES alg-mismatch guard).

### Adapter — Postgres (`adapters/pgx/`)  — 1 confirmed · 4 risks · 9 nits

The adapters/pgx module is high quality: every query is fully parameterized (no SQL injection surface), every WHERE clause is tenant-scoped, all pgx.Rows are defer-Closed with rows.Err() checked, nullable time columns are correctly scanned through *time.Time, and the recently-hardened atomic paths (identity CTE-based DeleteUser/UpdateUserEmail, keystore advisory-locked CreateTenant, mfa transactional replace/consume) are sound. The migration runner's single-implicit-transaction trick (appending the version INSERT to the argless Exec) makes version recording atomic with each file. One confirmed medium-severity availability/perf defect: oauth GetProvider decrypts the client_secret on every call before the cache check, so a KEK blip defeats a warm cache and every cached OIDC login still pays a KEK round-trip. Remaining items are non-reproducible edge-case risks (degraded non-transactional fallback paths) and a batch of documentation/idempotency-consistency nits.

### Passkey / WebAuthn (`passkey/`)  — 1 confirmed · 3 risks · 6 nits

The passkey (WebAuthn) unit is unusually well-hardened: secure-by-default UV (zero value coerced to VerificationRequired and propagated into SessionData, verified by tests), fail-fast NewService (nil store, <32-byte cookie key, missing ChallengeStore all rejected), HMAC-SHA256 authenticated ceremony cookie compared with hmac.Equal (constant time), server-side single-use challenge consumption before verification that correctly closes the sign-count-0 replay hole for both username and discoverable flows, tenant-scoped credential lookups, and proper clone-counter rejection. Challenge entropy comes from go-webauthn (crypto/rand) and origin/RPID validation is delegated to go-webauthn v0.17.4 (which requires RPOrigins). I found no critical/high/medium correctness or security defect. The only confirmed issue is a wrong HTTP status code for attestation-policy rejections. The remainder are risks (fail-closed edge cases) and idiomatic nits.

### Tokens — JWT (`tokens/jwt/`, `basic`, `memory`)  — 0 confirmed · 4 risks · 12 nits

The JWT core is unusually well-hardened: the alg-confusion defense (resolve signer by kid THEN pin token.Method.Alg() to the signer's algorithm) is correct for both the static keyfunc and the per-tenant keyfunc, "none" and RS256->HS256 confusion are rejected, JWKS never emits HMAC "k" material, weak HMAC keys are refused unless the test-only InsecureAllowWeakKey is set, refresh tokens/API keys use crypto/rand with enforced minimum lengths, and tenant binding on the verify path cannot be bypassed (verifyAccessToken is unexported and only reachable through VerifyAccessTokenForTenant, which enforces claims.TenantID == tenantID). The CachingKeyStore generation-guard correctly prevents caching a pre-invalidation keyset. I found no reproducible critical/high defect in the signing/verification/rotation paths. The concerns that remain are a non-atomic consume-then-issue window in Rotate, unbounded memory growth in CachingKeyStore, and a cluster of doc/house-style nits (stale references to a non-existent public VerifyAccessToken, %w wrapping vs the errors.Join house style, and an inaccurate KeyStore-fallback doc).

### Passwords (`passwords/`: argon2, breach, policy)  — 0 confirmed · 3 risks · 9 nits

The passwords unit (argon2 hasher, hibp/offline breach checkers, default/passphrase policies, hashertest contract) is well-engineered and heavily regression-tested. Argon2id uses crypto/rand salt, subtle.ConstantTimeCompare, cost floors clamped up to OWASP-2021 minimums, a MaxMemoryKiB ceiling and per-thread-min guard that prevent OOM/panic on tampered stored hashes, empty-password and oversized-input short-circuits that preserve timing symmetry with the decoy path, and context-cancellation checks before the KDF. HIBP correctly sends only the 5-char SHA-1 prefix (k-anonymity), caps the response, distinguishes truncation from not-breached, and honors an explicit fail-open/closed posture; offline mirrors the same threshold semantics. Policies count runes not bytes and normalize denylist entries against re-spacing. I found no CONFIRMED reproducible defect; findings are style/consistency nits, a few test-coverage gaps on error paths, and low-severity posture risks that are documented-by-design.

### Facade & internal (`actor.go`, `doc.go`, `internal/`)  — 0 confirmed · 3 risks · 9 nits

The facade unit (root actor.go/doc.go plus internal httputil and doctest tool) is small, defensive, and well-tested. The Actor/Principal scope helpers are correct and exhaustively covered; httputil's origin/CSRF helpers use strict exact-match semantics with safe fail-closed behavior. I found no reproducible correctness or security defect (nothing for confirmed[]). The notable observations are advisory: httputil.OriginAllowed is dead code in production (its permissive empty-allowlist default is a documented footgun that prod handlers deliberately bypass with their own strict copy), the doctest tool silently swallows parse errors and can false-green on unexpected `go doc` failures, doc.go slightly overstates the root API surface, and several httputil helpers lack direct tests.

### Supporting (`event`, `ratelimit`, `janitor`, `health`, `webapp`, `examples`, `adapters/otel`)  — 0 confirmed · 2 risks · 8 nits

This unit is small, defensive, and generally high quality. All TokenBucket map access is correctly serialized under a single mutex (Allow/Cleanup/KeyCount/evictOne), the maxKeys cap invariant holds (exactly one eviction before each insert), event emission recovers and logs sink panics, and webapp enforces CSRF-by-default by refusing to build without TrustedOrigins. I could not construct a concrete, reproducible failure/panic/security hole in any non-test source here, so there are no CONFIRMED blocking findings. Findings are limited to a deprecated OTel API, a misleading eviction doc, a silently-swallowed janitor panic (observability/DoS-signal gap), one webapp misconfiguration footgun, and coverage gaps.

