# Independent security audit — scope and request for proposals

> **Status: not yet commissioned.** This document is the scope the maintainers use to obtain
> quotes for, and contract, an **independent third-party human security audit** of egauth. No
> external auditor or firm has been engaged, no audit has been performed, and no audit report
> exists. The project's review to date is AI-assisted plus the author's engineering review; see
> [`AUDIT.md`](../../AUDIT.md) for the honest disclosure and the current ledger. Nothing in this
> document is a finding, a result, or evidence that an audit happened.

## 1. Purpose

egauth is an embeddable Go authentication library. Its own review history is disclosed honestly in
[`AUDIT.md`](../../AUDIT.md): the security review behind v1 is **AI-driven only** and the residual
risk of that status is explicitly documented, not hidden. This document prepares the single
highest-value assurance step still outstanding before v1 — commissioning qualified, independent
humans to review the code and its security claims — and does so in a way that is decision-ready:
prioritized scope, required deliverables, qualification bar, evidence package, and a rough effort
estimate so the maintainers can solicit comparable quotes.

The intended outcome of the engagement is a publishable report whose findings are reproduced,
triaged, fixed where accepted, and retested, followed by a truthful update of the audit ledger in
`AUDIT.md`. The report is the deliverable of the *engagement*; this document is only the plan for
it.

## 2. System under review

| | |
|---|---|
| Project | `github.com/JLugagne/egauth` (repository: `JLugagne/libauth`) |
| Type | Embeddable Go library (not a service or framework); consumers wire their own router, storage, mail/SMS delivery |
| Language / toolchain | Go 1.26 (pinned for the life of v1) |
| Size | ≈72.8k lines of Go in the core module, ≈5.7k in the nested `adapters/pgx` module (including tests) |
| Modules | Core: `identity`, `issuance`, `tokens` (+ `tokens/jwt`, `tokens/basic`), `sessions`, `passwords` (+ `argon2`, `policy`, `breach/*`), `mfa`, `otp`, `passkey`, `oauth` (+ `oauth/providers`), `authflow`, `webapp`, `keystore`, `ratelimit`, `event`, `health`, `janitor`, `revocation`; adapters: `adapters/pgx`, `adapters/otel` |
| Audit commit | To be pinned at engagement start: a specific commit SHA of the hardened v1-readiness tree (signed tag where available). The maintainers will record the SHA in the evidence package and in the resulting ledger entry. |

### Architecture and threat-model pointers (provided to the auditor)

- [`AUDIT.md`](../../AUDIT.md) — the honest review-status ledger and disclosure policy.
- [`SECURITY.md`](../../SECURITY.md) — the detailed security model/source of record: what the
  library guarantees, what the consumer must do, CSRF/origin policy, rate-limiting posture,
  constant-time strategy and benchmark evidence, account-existence disclosure, release
  verification.
- [`docs/security-guarantees.md`](../security-guarantees.md) — the per-module guarantee/consumer
  responsibility matrix.
- [`docs/content/docs/architecture.md`](../../docs/content/docs/architecture.md) and
  [`.llms/architecture.md`](../../.llms/architecture.md) — design model, Service/Store split,
  composition graph, cross-cutting seams, multi-tenancy model.
- [`docs/protocols/refresh-family.md`](../protocols/refresh-family.md) — refresh-token family
  state machine (states, transitions, invariants).
- [`docs/content/docs/sdk/security-hardening.md`](../../docs/content/docs/sdk/security-hardening.md)
  — hardening guide for integrators.
- [`RELEASING.md`](../../RELEASING.md) — release/tag-signing/SBOM/provenance process.

## 3. Prioritized scope areas

Coverage is **risk-prioritized, not uniform**. Reviewers should spend effort where a prior
white-box pass found systemic weakness and where a mistake would be catastrophic, rather than
sampling all ~72k lines evenly. The numbered areas below are the required minimum; quotations
should state coverage per area and any area the bidder proposes to expand or drop.

### (a) Post-auth issuance pipeline and every login flow — highest priority

One chokepoint (`issuance.Pipeline.Issue`) is supposed to terminate every interactive login path,
re-load authoritative account state, enforce tenant binding, propagate `MustChangePassword`, apply
the MFA gate once, and emit one uniform audit event. Review:

- Whether **every** login flow actually terminates in the pipeline and none can mint a session
  directly: password login/registration, magic link, OAuth/OIDC callback (with and without the
  `authflow` engine), `authflow` minter, MFA step-up, OTP verify, passkey login and discoverable
  login, and the `webapp` preset.
- Failure paths and races: rejected/aborted issuance mints nothing; disabled and soft-deleted
  accounts are refused on every flow; a caller cannot clear an authoritative
  `MustChangePassword`; claim rebuilding at issuance vs. refresh; interim MFA tokens cannot
  harvest a full renewable pair.
- The cross-flow invariant suite (`internal/loginflowtest`) — whether its table really covers
  every exported constructor and whether invoking it would catch a bypass.

### (b) OAuth / OIDC protocol security

Review the authorization-code + PKCE flow and the static OIDC path against current guidance
(OAuth 2.0 Security Best Current Practice / RFC 9700, OIDC Core):

- `state`/PKCE-verifier/nonce generation, entropy, binding, single-use, constant-time comparison,
  and the HMAC-authenticated, `__Host-` host-locked state cookie (including the minimum
  `MinStateSigningKeyLength` gate and fail-closed behavior on missing/short keys).
- OIDC `id_token` validation: algorithm pinning, `iss`/`aud`/`azp`/`exp`/`nonce` checks, JWKS
  fetching/rotation, and cross-issuer confusion.
- SSRF: `oauth.SafeHTTPClient` and the static-discovery/JWKS fetch path — loopback/link-local/
  RFC1918/RFC6598/multicast guards, DNS-rebinding safety, redirect refusal, and that discovered
  endpoints are validated before use. Attempt to bypass through provider configuration,
  tenant-controlled issuers, redirects, IPv6-mapped addresses, or alternative IP encodings.
- Account linking/just-in-time provisioning: unverified-email refusal by default, no auto-link by
  email, deleted-account handling, and tenant scoping of state and identities.
- The `oauth/providers` presets (Apple, Auth0, Cognito, Discord, Facebook, GitHub, GitLab, Google,
  Keycloak, LinkedIn, Microsoft, Okta) for provider-specific quirks.

### (c) Token and session state machines

Review with the state-machine document as the specification:

- Refresh-token rotation, single-use consumption, family chaining, theft detection/replay
  revocation, the reuse grace window and concurrent-rotation semantics, tenant immutability across
  rotations, and carry-forward of `MustChangePassword`, `AMR`, and `auth_time`.
- Atomicity and race-freedom of the consumer-facing store contracts (`ConsumeRefreshToken`,
  TOTP `MarkTOTPUsed`, attempt increments): compare the in-memory and `pgx` implementations
  against the interface contract and probe TOCTOU windows under concurrency. A non-atomic
  third-party adapter must not be able to silently disable replay detection.
- JWT issuance/verification: algorithm pinning and key-type confusion, key length/denylist
  gates, JWKS publication, keystore rotation, tenant binding (`MultiTenant`,
  `VerifyAccessTokenForTenant`), and cookie handling (`__Host-` prefixes, `SameSite`, clearing
  semantics on rotation/reuse).
- API-key lifecycle (PAT vs. service token): issuance entropy, at-rest hashing, scope and
  principal-kind enforcement, revocation, expiry, and audit events.
- Step-up/AAL: `WithRequiredAMR` fail-closed behavior, `WithMaxAuthAge` freshness, and the
  interim-token boundary.
- Server-side sessions: idle/absolute lifetime, fixation defense (`Rotate`), revocation, and
  store-bound eviction behavior.

### (d) Passkey / WebAuthn ceremony

Review the `passkey` module and the `passkey/passkeytest` helper:

- Ceremony-cookie sealing (HMAC construction, key source/length/denylist, `__Host-` host-lock,
  single-use, expiry) and the server-side challenge store (replay protection, atomic consume).
- Registration/authentication/discoverable-login verification: RP ID and origin validation,
  challenge binding, user-verification default, signature-counter/clone handling, and the
  account gate for disabled/deleted users.
- Tenant resolution for discoverable login and whether the `passkeytest` authenticator faithfully
  models a real WebAuthn client (it must not make tests pass where real credentials would fail).

### (e) Custom cryptographic glue and constant-time claims

The library deliberately implements small protocol/crypto glue itself rather than using a
framework; review that glue and audit the accuracy of the written constant-time guarantees:

- `authflow` flow-token sealing, the OAuth state cookie MAC, passkey ceremony-cookie MAC, and any
  other cookie sealing/signing; HMAC key handling and domain separation.
- Selector/verifier token scheme, `tokens.HashToken` usage, MAC and token comparisons — verify
  they are constant-time and never short-circuit or branch on secret bytes. Search for `==`,
  `bytes.Equal`, map lookups or length checks applied to MACs/tokens/password-derived values.
- Randomness sources for all secrets, nonces, states, selectors, verifiers, and IDs.
- Argon2id parameter parsing/bounds checks and the decoy-hash enumeration defense.
- The claimed constant-time properties (documented as structural with benchmark *evidence*, not
  proof): attempt to falsify them with timing measurements under controlled conditions, and
  report any claim that is overstated.

### (f) Multi-tenant isolation

Every tenant-scoped Store/Service method takes an explicit `tenantID`; single-tenant uses the
empty partition via `SingleTenant` facades. Review:

- Cross-tenant IDOR/authorization on every externally supplied identifier (user IDs, family IDs,
  API-key IDs, credential IDs, session tokens, OAuth state) and whether `ErrTenantMismatch` is
  returned rather than a not-found that leaks existence.
- Tenant resolvers in the HTTP middleware: fail-closed when resolution returns empty, no fallback
  to the tenant-unaware verification path.
- Tenant binding of OAuth state/callbacks, step-up, refresh rotations, passkey discoverable login,
  and audit events.
- Store-level tenancy: composite keys and uniqueness constraints in `pgx` and in-memory stores,
  including any key-collision/overwrite scenarios.

### (g) Supply chain and release provenance

- Dependency selection and pinning (`go.mod`/`go.sum`/`go.work`, committed tool versions),
  `govulncheck` posture, CI workflow integrity (`.github/workflows/`), and the nested-module
  `replace`/release dance.
- Release provenance: signed tag creation and verification
  (`scripts/verify-release-tag.sh`, gitsign/cosign/OpenPGP/SSH), SBOM generation and attestation
  (`RELEASING.md`, `Makefile`), retract directives, and module-proxy behavior.
- Provider/example key material must be denied or generated, never published.

### Out of scope (unless separately contracted)

- Applications built on top of egauth, their deployment infrastructure, and their configuration.
- Formal verification/differential proof of constant-time properties.
- Penetration testing of a deployed reference service (the library ships no server); a black-box
  exercise against the bundled `examples/fullstack` app can be added as an option.
- Non-security correctness/performance review, and review of unreleased branches other than the
  pinned audit commit.

## 4. Required deliverables (contract requirements)

1. **Findings report.** One entry per finding with: unique ID, title, severity
   (Critical/High/Medium/Low/Informational) with a stated rationale (CVSS or equivalent),
   affected component/version/commit, description, impact, **reproduction steps or proof of
   concept**, remediation guidance, and references. Findings must be reproducible by the
   maintainers from the report alone.
2. **Scope, methodology, and independence statement.** Explicitly list what was in and out of
   scope, the audit window, standards/methodologies used (e.g. OWASP ASVS/WSTG, RFC 9700, NIST
   SP 800-63B), tools, coverage per area from Section 3, limitations, and a signed statement that
   the audit was performed independently and that findings were not influenced by the maintainer
   or contingent on the outcome.
3. **Retest pass.** After accepted findings are fixed, re-verify each fix on the fix commit and
   deliver a retest addendum with per-finding status (fixed / partially fixed / unresolved /
   accepted risk). Include at least one retest round within the contract; state the cost of
   additional rounds.
4. **Publication permission.** Written permission to publish the report, or a public summary plus
   a private full report, at the maintainers' choice, with a coordinated-disclosure window for
   critical findings. If publication is restricted, the auditor must state why and what may be
   published (the ledger needs a link or a clear statement of publication status).
5. **Coverage matrix.** A per-area statement of what was reviewed and what was not, matching
   Sections 3(a)–(g).
6. **Executive summary suitable for `AUDIT.md`.** Auditor name/firm, date(s), commit, scope,
   findings count by severity, report link, and overall opinion — written for a public reader.

## 5. Auditor qualification criteria

Bids must demonstrate all of the following; certifications alone are not sufficient:

- **Go and Go-crypto depth.** Demonstrated review of production Go, especially `crypto/*`,
  `net/http`, `database/sql` patterns, and concurrency.
- **Authentication-protocol experience.** OAuth 2.0/2.1 and OIDC (PKCE, state/nonce, token
  binding), JWT/JWK and algorithm-confusion pitfalls, WebAuthn/FIDO2 ceremonies, refresh-token
  rotation/theft detection, and session management. Familiarity with RFC 9700, OIDC Core, RFC
  6238, and NIST SP 800-63B is expected.
- **Sample work.** At least two redacted public (or referenceable) audit reports of comparable
  scope, ideally on Go or identity code, so the maintainers can judge report quality.
- **Named team.** A named lead auditor and an independent internal reviewer for the report, with
  relevant CVs. The lead must be reachable for questions during the engagement.
- **Independence and conflicts.** A signed declaration of no material conflict of interest (no
  employment/contracting relationship with the maintainers in the last 24 months; no
  compensation contingent on findings). Willingness to sign an NDA covering the private
  pre-publication findings and any non-public evidence.
- **Capacity and timeline.** Committed dates, capacity for the retest round, and willingness to
  publish.
- **Insurance / liability.** For firms, professional liability coverage and a standard limitation
  of liability are expected; for individuals, a stated professional indemnity position.

## 6. Evidence package provided to the auditor

The maintainers will assemble and hand over, over a secure channel:

1. **Repository snapshot pinned at one commit.** A commit SHA (signed tag where available) of the
   post-hardening tree; the exact pin is recorded in the ledger entry. The tree is immutable for
   the duration of the audit.
2. **Build and test instructions.** Go 1.26 toolchain; core module is Docker-free:
   `GOWORK=off go test ./...`, `GOWORK=off go vet ./...`, `go run ./internal/doctest`,
   `make test-unit` (no Docker), `make check` (lint/vet/vulncheck). The `adapters/pgx` module
   requires Docker for `testcontainers`: `cd adapters/pgx && go test ./...`. The maintainers will
   confirm a green build/test run at the pinned commit and provide the output.
3. **Architecture and design corpus.** The pointers in Section 2, plus the tracked `.llms/`
   module notes and `README.md` module inventory.
4. **Threat model / source of record.** `SECURITY.md`, `docs/security-guarantees.md`, and the
   refresh-family state-machine document.
5. **Prior findings corpus.** The maintainers' complete prior AI-assisted review material —
   finding-by-finding descriptions, the confirmed-issue remediation work, and the corresponding
   fix diffs/commits — provided under the engagement's confidentiality terms. It is deliberately
   **not** part of the published repository. The auditor is expected to treat it as untrusted
   input and independently verify, not trust, its conclusions.
6. **Reproduction harness.** The `e2e-security/` suite, `test/` integration tests, and
   `examples/fullstack` reference app, which can be used to reproduce and extend PoCs.
7. **Release/provenance material.** `RELEASING.md`, CI workflows, `scripts/`, `Makefile` pinned
   tool versions, and generated SBOMs.
8. **Communication and disclosure plan.** Secure reporting channel, weekly check-ins, an
   out-of-band path for critical findings, and the coordinated-disclosure expectations from
   `SECURITY.md`.
9. **A written answer sheet** for auditor questions about intended usage and trust boundaries
   (the maintainers commit to answering within two business days so the time-box is not consumed
   by clarification).

## 7. Estimated effort

Rough order of magnitude for planning and comparing quotes. Assumes an experienced Go security
auditor with the Section 5 background, access to the evidence package, and maintainer Q&A within
two business days. Does **not** include maintainer remediation time or feature changes.

| Track | Area | Auditor-days |
|---|---|---|
| A | Issuance pipeline and all login flows | 4–6 |
| B | OAuth/OIDC (state/nonce/PKCE/SSRF/linking) | 4–6 |
| C | Token/session state machines, API keys, step-up | 4–6 |
| D | Passkey/WebAuthn ceremony and test helper | 2–3 |
| E | Custom crypto glue and constant-time claims | 2–3 |
| F | Multi-tenant isolation | 2–3 |
| G | Supply chain and release provenance | 1–2 |
| — | Reporting, peer review, and coordination overhead | 2–4 |
| — | Retest round for accepted findings | 1–3 |
| | **Estimated total (prioritized scope)** | **22–36 auditor-days** |

- Two auditors working in parallel can compress the calendar to roughly 4–6 weeks; a single
  auditor is likely 7–10 calendar weeks. The maintainers expect a fixed-fee proposal per track or
  a day-rate with a not-to-exceed cap.
- A **full-surface review of all ~78k lines** (uniform coverage instead of the prioritized
  tracks) is estimated at **60–90 auditor-days** and is not required for the first engagement.
- Retest cost is included above for one round; quotes must state the price of additional rounds.
- Currency/pricing is intentionally excluded here; the maintainers will set a ceiling after
  quotes are opened, using this effort range as the primary driver.

## 8. Commissioning checklist (who does what, in order)

Actors: **Maintainer** (project owner), **Reviewer** (a second maintainer or trusted independent
volunteer), **Auditor** (selected firm/individual), **Legal/Finance** (if applicable).

| # | Step | Who | Action and gate |
|---|---|---|---|
| 1 | Finalize scope and budget | Maintainer | Confirm this scope against the current tree; set the maximum budget and target dates. Prerequisite: the hardening work to be audited is merged and CI is green. **Gate:** scope commit frozen and recorded. |
| 2 | Prepare evidence package | Maintainer | Assemble Section 6 items at the pinned commit; run the build/test commands; verify tag signature where applicable. **Gate:** a clean, reproducible package with recorded command output. |
| 3 | Request quotes | Maintainer | Send this document to a shortlist of qualified auditors; require the Section 9 response format and a fixed-fee or capped quote. |
| 4 | Evaluate and select | Maintainer + Reviewer | Score proposals against Section 5/9; check references; screen for conflicts. **Gate:** written selection rationale. |
| 5 | Contract and NDA | Maintainer + Legal/Finance | Execute an SOW referencing this scope: deliverables, dates, retest terms, publication permission, confidentiality, payment schedule, liability. **Gate:** signed contract before any code leaves the project. |
| 6 | Provide environment and kickoff | Maintainer + Auditor | Deliver the pinned snapshot and evidence package over the secure channel; confirm the auditor can build and run the tests; agree the check-in and critical-finding paths. **Gate:** auditor confirms the environment reproduces the recorded green run. |
| 7 | Execute audit | Auditor | Perform the review; hold weekly check-ins; report critical findings out-of-band immediately per `SECURITY.md`. |
| 8 | Triage findings | Maintainer + Reviewer | Reproduce each finding, assign/confirm severity, and classify as fix / accept-with-rationale / track privately. **Gate:** every finding has a disposition. |
| 9 | Remediate | Maintainer | Fix accepted findings; document accepted risks and rationale; keep each fix reviewable and tested. **Gate:** fixes green on CI at the fix commit. |
| 10 | Retest | Auditor | Verify each accepted fix on the fix commit; deliver a retest addendum. Remaining findings repeat steps 8–10 once more if needed. |
| 11 | Final report | Auditor | Deliver the complete report plus the executive summary, coverage matrix, and independence statement. |
| 12 | Publish | Maintainer | Publish the report (or public summary) in the repository or a durable public location; link it from `AUDIT.md`. |
| 13 | Update the ledger and disclosures | Maintainer | Replace the pending template in `AUDIT.md` with the real entry (auditor, date, commit, scope, findings counts, report link, retest status). Update the disclosure surfaces only if the audit status actually changes, in the same PR: `README.md`, `SECURITY.md`, `llms.txt`, `doc.go`, `CHANGELOG.md` — keeping `disclosure_test.go` and the canonical sentence in lock-step. **Gate:** the honest disclosure still matches reality. |
| 14 | Close out | Maintainer | File follow-up tickets for open findings (public or private as appropriate); announce the result; schedule the next review before the report is a year old. |

## 9. Response format and evaluation

Proposals should be concise and include: team and named lead (with CVs), two referenceable reports,
methodology and per-area coverage plan from Section 3, estimated effort and calendar, fixed-fee or
capped pricing with retest pricing, independence/conflict declaration, publication stance, and
availability. Maintainers will evaluate with approximate weights: audit depth and sample report
quality (35%), coverage/methodology fit (25%), independence and references (15%), timeline (10%),
and price (15%), with the rationale recorded at selection time.
