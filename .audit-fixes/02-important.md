# Important fixes (0 / 19)

Expected by serious adopters.

---

## [x] I1 — otp HTTP handlers (enumeration-safe) — DONE
**Where:** new `otp/handlers.go`. **Problem:** otp imports no net/http; every adopter must reimplement enum-safe error collapsing. **Fix:** issue/verify `http.HandlerFunc` factories mirroring identity/mfa; collapse `ErrInvalidCode`/`ErrCodeNotFound`/`ErrTooManyAttempts` into one response. **Test:** handler tests for collapse + status mapping.

## [x] I2 — CSRF on tokens RefreshHandler / LogoutHandler — DONE
**Where:** `tokens/handlers.go`. DONE: `WithTrustedOrigins` + Origin/Referer check → 403. NOTE: shared double-submit-cookie helper not shipped (origin allowlist used instead). **Problem:** cookie-auth state-changing POSTs have no origin check (not even opt-in); identity is opt-in only. **Fix:** add `WithTrustedOrigins`/shared CSRF middleware to token handlers; consider a reusable double-submit-cookie helper. **Test:** cross-origin POST rejected when origins configured.

## [x] I3 — RequestEmailVerification enumeration safety — DONE (commit 6076b2f)
**Where:** `identity/service.go:300-302`. **Problem:** returns store error (500) vs uniform 204 — leaks live/same-tenant userID. **Fix:** swallow ErrUserNotFound at service / always 204 at handler (match reset/magic-link). **Test (confirm-first):** unknown/foreign userID currently 500; assert 204.

## [x] I4 — Email validation + normalization — DONE
**Where:** `identity` Register/LinkOrCreateIdentity + handlers. **Problem:** verbatim email (only TrimSpace); byte-exact uniqueness → `User@x.com`≠`user@x.com`; empty/malformed registers. **Fix:** `net/mail.ParseAddress` + trim+NFC+lowercase; enforce uniqueness on normalized form. **Test (confirm-first):** case-variant dup registers today; assert rejected/normalized.

## [x] I5 — Authenticated change-email flow (verify-before-switch) — DONE
**Where:** `identity/service.go` + handlers + Store. DONE: `RequestEmailChange`/`ConfirmEmailChange` on Service (kind `email_change`, new email carried as token metadata, delivered to the NEW address via new `Mailer.SendEmailChange`); `RequestEmailChangeHandler`/`ConfirmEmailChangeHandler` + `WithEmailChangeField`. Atomicity: new `Store.UpdateUserEmail` swaps `users.email`+`email_verified_at` AND re-keys the password identity's `provider_id` (password identities are keyed by email) in one atomic op — single CTE on pgx, locked multi-update on memory — so a uniqueness conflict on either index aborts the change. Confirming (token went to the new address) marks the new address verified. **Problem:** no ChangeEmail; only internal Store.UpdateUser. **Fix:** request → token to NEW address → confirm → atomic swap + reset EmailVerifiedAt. **Test:** swap-only-after-confirm, normalize, taken-up-front + claimed-in-interim, single-use, expiry, kind isolation, deactivated-account, unknown-user; handler 401/delivery/error-mapping; cross-backend `Contract: Change Email` (memory + pgx).

## [ ] I6 — User-facing account deletion / deactivation (+GDPR)
**Where:** `identity/service.go` + handlers. **Problem:** DeleteUser is Store-only, internal orphan-comp only. **Fix:** `DeleteAccount`/`DeactivateAccount` on Service + handler; cascade revoke sessions/refresh families/MFA/passkeys; consider hard-erase + data-export. **Test:** delete cascades + revokes.

## [ ] I7 — Breach-password check: ship HIBP k-anonymity impl
**Where:** new `passwords/breach/hibp` sub-pkg. **Problem:** `BreachChecker` is interface-only; no client ships. **Fix:** HIBP range API (only first 5 SHA-1 hex chars leave process), documented fail-open vs fail-closed; optional offline blocklist loader. **Test:** k-anon prefix only; mock HTTP; fail-mode behavior.

## [ ] I8 — Email/SMS delivery implementation + templating
**Where:** new `delivery/` (SMTP Mailer) + OTP Sender seam. **Problem:** Mailer interface wired but no impl, no templating; OTP/MFA have no Sender, no contact field. **Fix:** reference SMTP Mailer + message templating hook; delivery interface for OTP with contact-resolution seam; document SMS story. **Test:** template render; Mailer against a fake SMTP.

## [ ] I9 — OAuth OIDC id_token / nonce / JWKS validation
**Where:** `oauth/`. **Problem:** identity from access-token userinfo GET only; no id_token/nonce/JWKS → no replay protection; not true OIDC. **Fix:** parse+validate id_token (JWKS sig, iss/aud/exp), nonce minted at Begin + bound through state cookie. **Test:** reject bad sig/iss/aud/nonce; accept valid. **Follow-on:** generic OIDC provider (discovery) is the prerequisite for per-tenant provider assignment — see [feature-per-tenant-oidc.md](feature-per-tenant-oidc.md).

## [ ] I10 — JWT signing-key rotation (kid / keyset / overlap)
**Where:** `tokens/jwt/issuer.go`. **Problem:** single static SecretKey; rotation invalidates all live tokens. **Fix:** keyset with primary signer + secondary verifiers (kid-tagged), overlapping-validity rollover; optional JWKS for asymmetric. **Test:** token signed by prev key still verifies during overlap; rotation doesn't break live tokens.

## [ ] I11 — Audit logging / security-event hooks / slog seam
**Where:** services across modules. **Problem:** no logging/events/observer at all; enum-safe handlers silently swallow store/mailer errors (outage invisible). **Fix:** optional event-hook/observer interface emitted from services (login ok/fail, lockout, reuse-detected, MFA enroll, family revoke) + injectable `*slog.Logger` seam. **Test:** events emitted on each lifecycle action; swallowed-error path still logs.

## [ ] I12 — Sessions refresh / sliding expiry / rotation + fixation
**Where:** `sessions/service.go`. **Problem:** Create/Validate/Revoke only; ExpiresAt fixed; token never rotated. **Fix:** `Touch`/`Refresh` (sliding) + `Rotate` (new token same logical session); rotate id on privilege elevation. **Test:** Touch extends expiry; Rotate changes token, invalidates old.

## [ ] I13 — Passkey discoverable / usernameless login
**Where:** `passkey/service.go`. **Problem:** Begin/FinishLogin require known userID; no resident-key flow. **Fix:** `BeginDiscoverableLogin`/`FinishDiscoverableLogin` via go-webauthn discoverable API (resolve user from credential userHandle). **Test:** login resolves user without prior username.

## [ ] I14 — Passkey Finish-ceremony end-to-end test
**Where:** `passkey/*_test.go`. **Problem:** FinishRegistration/FinishLogin verification path, toStored, ErrCredentialCloned, onLoginSuccess never exercised. **Fix:** software-authenticator / canned attestation+assertion fixtures driving full Finish incl. clone detection + sign-count persistence. **Test:** is the deliverable.

## [ ] I15 — Re-authentication / step-up flow (sudo mode) + gate DisableTOTP
**Where:** `tokens/middleware.go`, `mfa`. **Problem:** only AMR transport+gating; nothing re-prompts/freshens; DisableTOTP has no step-up. **Fix:** re-auth flow minting fresh higher-AMR short-lived token and/or auth_time freshness check; gate DisableTOTP. **Test:** stale auth_time rejected; DisableTOTP requires step-up.

## [ ] I16 — Background cleanup / GC of expired records
**Where:** all Store ifaces (tokens/sessions/otp/verification). **Problem:** no DeleteExpired/reaper; memory grows unbounded, pgx bloats (tokens retained for reuse detection). **Fix:** `DeleteExpired(ctx,...)` per Store (schedulable) + optional pgx TTL/partial indexes; document cadence. **Test:** DeleteExpired removes only expired; keeps consumed-but-needed token rows where required.

## [ ] I17 — Secret redaction on credential-bearing types
**Where:** `tokens/token.go` (TokenPair.Access/Refresh, APIKey.Token), session token. **Problem:** plain strings, no `json:"-"`/String()/LogValue masking → logging struct leaks live creds. **Fix:** redacting secret type or String()/MarshalJSON/LogValue masking + `json:"-"` where apt. **Test:** fmt/json of struct does not contain plaintext.

## [x] I18 — Config validation / fail-fast at startup — DONE (jwt) — follow-up: identity/sessions/mfa constructors
**Where:** `tokens/jwt/issuer.go` New[C] (DONE: panics on empty key + `Config.Validate`); identity/sessions/mfa NewService (still TODO — add basic validation). **Problem:** jwt.New returns no error, silently accepts empty SecretKey + zero TTLs. **Fix:** make jwt.New return error; reject empty SecretKey, non-positive AccessTTL/RefreshTTL, empty Issuer; add basic validation to other constructors. **Test (confirm-first):** empty SecretKey currently succeeds; assert error.

## [ ] I19 — Tenant enforcement consistency across backends
**Where:** memory + pgx stores (mfa/otp/passkey + others). **Problem:** pgx enforces ErrTenantRequired only on some writes; reads/deletes query tenant_id=''; memory rarely enforces; never tested. **Fix:** enforce ErrTenantRequired uniformly on all write+read+delete (or define+document empty-tenant default); add contract tests for empty-tenant path. **Test (confirm-first):** empty-tenant read on pgx silently returns empty today; assert consistent behavior.
> Also in scope (found during I5 review): identity `UpdateUserEmail` follows the same whole-file pattern — pgx returns `ErrTenantRequired` on empty tenant, memory accepts it and succeeds; the `StoreContractTesting` callers all pass `useMultiTenant=true`, so the empty-tenant path is never exercised. Pin empty-tenant behavior for the whole identity Store (incl. `UpdateUserEmail`) here rather than special-casing one method.
