# Attack chains — egauth security audit 2026-09-08-1945

Commit audited: `6f16690`. Scope: library flaws as they propagate to consumer apps.
Finding corpus: AS-01..AS-04, IE-01 (= duplicate of AS-01), SECRETS-01/02,
WEB-01 (overlaps AS-04), WEB-02, CFG-01, injection (empty — no findings).

Known overlaps merged in the narratives below; JSON files left untouched.
Severity references are CVSS 3.1 as filed. "Combined severity" is a qualitative
judgment, not a re-scored CVSS — stated explicitly per chain.

---

## Chain 1 — Enumeration oracle feeds targeted forced-password-change evasion

**Findings:** AS-01 (5.3 Medium) + IE-01 (3.7 Low, same oracle, merged here) → AS-02 (4.3 Medium)

**Entry point:** Unauthenticated remote attacker against a consumer app using the
default `LoginHandler` / `webapp` preset (no `WithUniformAuthErrors`).

**Steps:**
1. Probe candidate emails with a single login attempt each (any password).
   Disabled accounts answer `429 account_locked` on the first attempt; unknown
   identifiers answer `401 invalid_credentials` (AS-01/IE-01). Real accounts
   additionally flip to 429 after the lockout threshold. Result: a validated
   username list plus disabled-vs-live partitioning, at one request per candidate.
2. Run credential-stuffing / password-spraying only against validated live
   accounts (oracle output), reducing noise and lockout burn versus blind spraying.
3. For a compromised must-change, MFA-enrolled account, complete the real second
   factor through `mfa.StepUpHandler` on default wiring (no `WithMustChangeResolver`).
   The interim token carries `MustChangePassword`, but the stepped-up family is
   minted with the flag dropped (AS-02).
4. The fresh refresh family replays `flag=false` across silent rotation, so
   `WithPasswordChangeGate` never diverts. With default unbounded refresh lifetime
   (`MaxRefreshLifetime=0`) the evasion persists until the next interactive login.

**Final impact:** Attacker-selected accounts converted into persistent sessions that
dodge a forced-password-change control (e.g. post-breach rotation, first-login or
admin-reset flows). Confidentiality/integrity impact is bounded by the prerequisite:
the attacker still needs the victim's password AND second factor (AS-02 is PR:L).
The oracle does not remove that bar; it only makes target acquisition cheaper and
quieter.

**Combined severity: NO raise beyond max individual (5.3 Medium).** The chain is
realistic for a library (every default consumer ships the oracle; every default
MFA consumer ships the drop), but composition is additive convenience, not a
privilege-escalation multiplier. If credentials + second factor are already
compromised, the session is attacker-controlled regardless; AS-02 extends its
useful life against one control. Do not score above Medium on this chain alone.

---

## Chain 2 — Disabled-account oracle feeds reset/magic-link liveness and delivery abuse

**Findings:** AS-01 (5.3 Medium) + IE-01 (merged, same oracle) + AS-03 (3.7 Low)

**Entry point:** Unauthenticated remote attacker; two surfaces: the default login
handler (oracle) and any consumer that uses the `identity` Service API directly
(`RequestMagicLink` / `RequestPasswordReset` return values or mailer invocation)
rather than only the uniform-204 HTTP handlers.

**Steps:**
1. Use the AS-01/IE-01 oracle to partition emails into unknown / live / disabled
   (disabled = immediate 429).
2. Call the Service-API reset/magic-link request for disabled-account emails.
   Mint-time gates check only `DeletedAt`, so a single-use selector/verifier token
   is minted and returned for delivery (AS-03), while unknown identifiers yield
   `("", nil, nil)`. Branching on the return value or on mailer invocation gives a
   second, independent liveness signal confirming the oracle result.
3. The suspended user receives credential email(s) they should not get; the token
   sits in their inbox / mail logs until expiry.

**Final impact:** Privacy leak (suspended-account liveness confirmation via two
channels), unwanted credential-email delivery to deprovisioned users (confusion,
help-desk load, phishing-ready pretext: "your disabled account just requested a
reset"). No account takeover: the consume-time gate (`consumeForLiveUser` rejects
`DisabledAt`) correctly refuses the token, as the PoC confirms.

**Combined severity: NO raise beyond max individual (5.3 Medium); effective impact
Low.** The combination corroborates enumeration and adds nuisance delivery, but the
kill-chain terminates at consume time. Do not score as an ATO chain. Remediation of
either end (uniform 401 at login, or mint-time `DisabledAt` check returning decoy
empty) breaks the corroboration loop.

---

## Chain 3 — Unsigned OAuth state cookie + Host-derived redirect_uri → login-CSRF / code diversion (lax providers only)

**Findings:** WEB-01 (3.4 Low) + AS-04 (3.4 Low, same unsigned/non-host-locked state
cookie, merged here) + WEB-02 (3.4 Low)

**Entry point:** Victim's browser lured to an attacker-influenced URL; attacker holds
one of: (a) sibling-subdomain cookie-write under a shared parent `Domain`
(`WithCookieDomain` set), or (b) a Host-poisoning position (misbehaving proxy / edge
that forwards attacker `Host` + `X-Forwarded-Proto`), plus a provider that honors
unregistered `redirect_uri` values.

**Steps:**
1. WEB-02 leg: victim opens `Begin` with poisoned `Host: evil.example` /
   `X-Forwarded-Proto: https`. With neither `WithRedirectURL` nor `WithAllowedHosts`
   set, `resolveRedirectURL` builds `redirect_uri=https://evil.example/...`, sends it
   to the provider in `AuthCodeURL`, and reuses it at the code exchange.
2. WEB-01/AS-04 leg: attacker self-mints an unsigned 5-field state cookie
   (state + PKCE verifier + nonce + provider + tenant of the attacker's choosing —
   e.g. the attacker's own IdP identity) and plants it via the cookie-write primitive
   (no `Begin` round trip needed; default `oauth_state` name is not `__Host-` locked).
   The callback's state/provider/tenant equality checks pass against the forged binding.
3. Victim completes the provider leg and returns through the callback; the handler
   exchanges the code and issues the app session cookies (204 + auth cookies in the
   PoC) bound to the **attacker's linked identity** — a classic login-CSRF / session-swap.
   With the WEB-02 leg added and a lax provider, the authorization code itself can
   additionally be delivered to the attacker's host, compounding swap into potential
   code interception.

**Final impact (capped):** Victim browses under the attacker's identity; secrets the
victim then enters (profile data, payment, subsequent credentials) land in an
attacker-visible account. Possible escalation to account confusion / data pollution.
NOT a direct victim-account takeover: the session belongs to the attacker's identity,
not the victim's.

**Combined severity: NO raise beyond Low in the general case.** Each leg already
assumes a strong precondition (cookie-write primitive; lax provider + Host control;
victim lure — AC:H/UI:R per both CVSS vectors), and strict providers — the common
case, enforcing exact `redirect_uri` registration — kill the WEB-02 leg outright,
leaving only the self-flow login-CSRF shape whose impact is session-swap, not ATO.
Composition widens the scenario slightly (swap + code diversion in one flow) but does
not create a new impact class. Fixing either default (`WithStateSigningKey` + `__Host-`
state name; explicit `redirect_uri` / `WithAllowedHosts` + ignoring `X-Forwarded-Proto`
without a trusted proxy) breaks the chain.

---

## Chain 4 — Copy-paste demo bundle: published keys + demo insecure wiring → total token/ceremony forgery on pasted deployments

**Findings:** SECRETS-01 (7.4 High) + SECRETS-02 (5.9 Medium), with non-finding
context: `examples/fullstack` demo wiring (`WithInsecureNoOriginCheck`,
`WithInsecureCookies`, per web.md § ruled-out, each with production comments)

**Entry point:** No victim interaction. Attacker targets a consumer deployment built
by copying `examples/fullstack/main.go` and/or the docs snippets without replacing
key material — a realistic vector for a library whose onboarding path is copy-paste.

**Steps:**
1. SECRETS-01 leg: victim deployment mints HS256 tokens with a publicly-known key
   (`"replace-with-a-32-byte-minimum-secret-in-production!"` or
   `"super-secret-32-byte-key-here!!!"` — both pass the 32-byte gate). Attacker feeds
   the published string into their own `jwt.New` instance and forges access tokens
   (arbitrary subject/tenant/scopes, `MustChange=false`) that the victim verifies —
   proven cross-instance in the PoC.
2. SECRETS-02 leg (same pasted deployment): passkey ceremony cookies are HMAC'd with
   an attacker-known key (32 zero bytes or `"very-secure-32-byte-secret-key!!"` —
   both pass the length gate, PoC-accepted by `passkey.NewService`). Attacker forges
   ceremony-cookie state (challenge binding).
3. The demo's adjacent insecure toggles, if copied along, remove the remaining
   friction (origin checks off, non-secure cookies), though they are commented as
   demo-only and are not themselves findings.

**Final impact:** Full authentication bypass on the pasted deployment: arbitrary
account/tenant impersonation via forged JWTs (C:H/I:H), plus ceremony-state forgery
on the passkey path (bounded by the still-required real WebAuthn ceremony, so the
JWT leg dominates).

**Combined severity: NO raise beyond max individual (7.4 High).** SECRETS-01 alone is
already total forgery on affected deployments; SECRETS-02 and the demo toggles add
breadth (second forged primitive, less friction) but no new impact ceiling. The honest
scoping note: the library defaults themselves are fail-closed (short keys panic,
signing/origin/secure-cookie defaults secure); this chain exists only in the
copy-paste-deployment population, which is exactly why the remediation is docs/example
hygiene (generation snippets, secret-manager guidance, denylist of the published
strings, all-zero-key rejection) rather than a core-verifier fix.

---

## Considered but NOT viable as chains (explicitly rejected)

- **AS-03 + AS-02 (disabled tokens feeding must-change bypass):** no path. Disabled
  principals are rejected at consume time (AS-03 terminates) and step-up requires a
  live authenticated session (AS-02 prerequisite). Minting a token for a disabled
  account does not yield a session to step up.
- **AS-03 + SECRETS-01 (reset token for disabled account + forged JWT):** no
  composition. The forged JWT path does not need the reset token, and the reset token
  does not help forge JWTs. Independent issues.
- **CFG-01 (govulncheck gap on `adapters/otel`) + anything current:** no concrete
  chain today. It is a latent supply-chain detection gap: a *future* OTel SDK CVE
  could ship silently in the observability adapter co-located with auth code. No
  known CVE is chained here (inventing one would be speculation); tracked as a
  defense-in-depth gap, not an active attack step. Remediation (govulncheck step for
  `adapters/otel`) closes the window without changing any current impact rating.
- **Anything + injection:** no composition surface. The injection audit found nothing
  to chain from (parameterized pgx queries, separator-safe state encoding, strict JWT/
  PHC parsing, no shell/XML/template/header sinks). This actively *breaks* classic
  escalation chains (no SQLi → auth bypass; no parser confusion → token forgery),
  which is why every chain above must earn its entry point through logic/defaults
  issues rather than injection.
- **WEB-02 standalone → open-redirect/token-theft:** rejected beyond what Chain 3
  claims. `successURL`/`failureURL` are static operator config (no `next` parameter),
  and Host-derived `redirect_uri` reflection additionally requires a lax provider.
  No standalone redirect-theft chain without both preconditions.
- **Physical access / staging-prod confusion / CI-secret theft:** out of scope per
  task; no chain constructed on those premises. (CI workflows hold no embedded
  secrets — ephemeral Postgres service password only; actions SHA-pinned.)

---

## Library-propagation note

All chains above are stated against consumer deployments, not the library repo
itself: AS-01 ships in the default `webapp` preset, AS-02 triggers on default MFA
wiring, WEB-01/WEB-02 trigger on default OAuth handler options, AS-03 triggers for
Service-API consumers, and SECRETS-01/02 trigger on copy-paste onboarding. A single
library-default fix (uniform 401 default; interim-claims fallback in step-up;
mint-time disabled check; signed `__Host-` state default; explicit redirect
requirement; example/docs key hygiene) therefore remediates the corresponding chain
across all consumers at once.
