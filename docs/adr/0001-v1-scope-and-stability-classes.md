# ADR 0001 — v1 module scope and stability classes

- **Status:** Proposed (maintainer decision pending)
- **Date:** 2026-09-10
- **Deciders:** repository maintainer
- **Scope:** documentation only. This record changes no behavior and no API. It proposes which
  packages the v1 SemVer promise should cover and assigns each module a stability class.

## Context

egauth is a multi-module toolkit: the core module ships account management, tokens, sessions,
second factors, federated login and a set of supporting seams, plus nested adapter modules for
PostgreSQL and OpenTelemetry. Tagging v1.0.0 turns every exported symbol in a frozen package
into a long-lived compatibility contract — it can then only change in a new major version.

The breadth of that surface is the risk this record addresses. A wide frozen surface must be
maintained, tested and kept secure for the life of v1, and every composition layer that chains
several modules together multiplies the combinations that must keep working. A narrow, deep,
independently tested core under the SemVer promise is a more defensible contract; everything
outside it can ship as explicitly experimental and keep evolving without forcing a major-version
break.

Constraints on the decision:

- Security-critical modules that already carry their own unit, contract and cross-module
  verification should be frozen.
- Convenience and composition layers that add surface without owning an independent security
  invariant are the candidates for `experimental`, not for the freeze.
- This decision changes no behavior and no API.
- Deleting or splitting working modules is not required; labels and documentation are enough.

## Stability classes

| Class | Promise |
|---|---|
| `frozen-v1` | The exported API is intended to remain backward-compatible for the life of v1. Breaking changes require a new major version. |
| `experimental` | No SemVer guarantee. The API may change or be removed in any release, including a patch. The package is maintained but not part of the compatibility contract. |
| `split` | Recommended to move to its own Go module so it can version independently of the core. |
| `deprecate` | Recommended for removal. The symbol keeps working for at least one minor release with a `// Deprecated:` marker before removal in the next major. |

## Module analysis and recommendation

| Module | Maturity | Test depth | Security criticality | Maintenance cost | Needed for core use cases | Recommendation |
|---|---|---|---|---|---|---|
| `identity` | Mature | 32 test files, ~7.3k LOC; 76% package (95% in-memory store); store + service conformance suites; cross-module suite | Critical | High | Yes | `frozen-v1` |
| `tokens` | Mature | 50 test files, ~9.4k LOC; 88% package, 86% `tokens/jwt`; store + issuer contract suites; JWT fuzz test | Critical | High | Yes | `frozen-v1` |
| `sessions` | Mature | 9 test files, ~1.8k LOC; 91%; store contract; CSRF, lifetime and rotation tests | Critical | Medium | Yes | `frozen-v1` |
| `passwords` | Mature | 11 test files; argon2 95%, policy 82%, breach clients 82–88%; hasher contract; Argon2id fuzz test | Critical | Low–Medium | Yes | `frozen-v1` |
| `mfa` | Mature | 13 test files, ~2.1k LOC; 82%; store contract; replay, lockout-decay and attempt-limit tests | High | Medium | Yes (second factor) | `frozen-v1` |
| `otp` | Mature | 8 test files, ~1.2k LOC; 75% package (98% in-memory); store contract; concurrency/TOCTOU tests | High | Low–Medium | Yes (passwordless/step-up) | `frozen-v1` |
| `passkey` | Mature | 23 test files, ~3.4k LOC; 82%; software-authenticator ceremonies, replay, property and fuzz tests | High | Medium–High | Yes (WebAuthn) | `frozen-v1` |
| `oauth` | Mature | 27 test files, ~5k LOC; 86%; state-binding property tests, redirect and SSRF hardening, cross-host tests | High | High | Yes (federated login) | `frozen-v1` |
| `oauth/providers` | Maturing | 82% with the provider tests; no independent conformance suite | High (delegates to `oauth`) | Medium–High (provider churn) | Optional | `experimental` |
| `keystore` | Newer | `keystoretest` contract + pgx integration; 68% package, 76% in-memory | Critical | Medium | Yes for multi-tenant deployments | `frozen-v1` |
| `issuance` | Small, stable | 1 test file; 85% | Critical (post-auth invariants) | Low | Yes (all interactive login paths) | `frozen-v1` |
| `webapp` | Maturing | 8 test files; 88%; routes, CSRF, rate-limit and login-uniformity tests | High (composes `identity`+`tokens`) | Low–Medium | Optional | `experimental` (proposal — see note) |
| `authflow` | Maturing | 8 test files, ~1.5k LOC; 83%; flow, step-up, lifecycle and fuzz tests | High (composes all login methods) | Medium | Optional | `experimental` |
| `adapters/pgx` | Mature | 23 test files, ~2.4k LOC; testcontainers integration per store against the core contract suites | High (persistence atomicity) | Medium | Optional backend | `frozen-v1` |
| `adapters/otel` | Small, new | `sink_test.go`; separate module | Low–Medium | Low | Optional | `frozen-v1` |
| `event`, `health`, `ratelimit`, `revocation`, `janitor` | Mature seams | event 96%, ratelimit 92%, janitor 94%, revocation 85%; `health` is interface-only | Low–Medium | Low | Supporting | `frozen-v1` |
| Subpackages (`tokens/jwt`, `tokens/basic`, memory stores, `*/storetest`, `passkeytest`) | Mature | Covered by the parent module's suites; `tokens/basic` 71%, `passkeytest` 89% | Varies | Low | Supporting | Follows the parent module |

### Recommendation summary

- **`frozen-v1`:** `identity`, `tokens` (and its subpackages), `sessions`, `passwords`, `mfa`,
  `otp`, `passkey`, `oauth`, `keystore`, `issuance`, `adapters/pgx`, `adapters/otel`, and the
  supporting seams `event`, `health`, `ratelimit`, `revocation`, `janitor`.
- **`experimental`:** `authflow`, `oauth/providers`; proposed for `webapp` (see below).
- **`split`:** none for v1. `oauth/providers` is the only realistic future split — moving the
  provider constructors to their own module would decouple provider churn from core tags — but
  that is a packaging change better taken deliberately than folded into the freeze.
- **`deprecate`:** none. Every module on this list has tests and a consumer-visible purpose.

### Notes on the notable calls

**`authflow` — experimental.** The package is a composition layer: it coordinates identity
resolution, lifecycle checks, MFA policy and credential issuance across password, magic-link,
OAuth and passkey logins. The post-authentication invariants it centralizes are already enforced
by the frozen `issuance` pipeline plus the per-handler gate (`identity.WithMFAGate` completed by
`mfa.StepUpHandler`). Freezing the engine would freeze a second, higher-level control path over
the same primitives, and every change to a login method would otherwise need to preserve two
public contracts instead of one. Applications that adopt the engine accept that its API may move.

**`webapp` — recommended experimental; requires a maintainer decision because the package doc
currently states the opposite.** The package is a small (≈380 LOC) convenience preset that wires
identity and tokens into one handler with secure defaults. It does not reimplement invariants,
but it does create a second frozen composition surface that must track changes to both underlying
modules. The recommendation is to keep it outside the SemVer promise and advertise the à-la-carte
handlers as the frozen path. Currently `webapp`'s package documentation states it is "frozen under
the v1 SemVer promise"; this ADR records the recommendation and the conflict but deliberately does
not rewrite that wording. If the maintainer keeps the freeze, the mitigations are to freeze only
`NewWebApp` and `Config` and treat every later addition as a new option, rather than growing the
preset into a third framework surface.

**`oauth/providers` — experimental.** The constructors are thin wrappers over `oauth.New`, but
each one encodes provider-specific endpoints, scopes and userinfo JSON that change on the
provider's schedule, not ours. Freezing them makes every upstream provider change a potential
v2 trigger. The core `oauth` package (PKCE, state binding, OIDC, SSRF-guarded fetches) stays
frozen; the bundled constructors are convenience.

**`keystore` — frozen despite being the newest module.** It is the per-tenant isolation layer for
signing material, it has its own contract suite and pgx integration tests, and it is a security
boundary rather than an optional convenience. Freezing it is the point of the isolation design:
a contract that absorbs additional secret types later without a break.

**Supporting seams — frozen.** `event`, `health`, `ratelimit`, `revocation` and `janitor` are
small, dependency-light interfaces that frozen modules depend on. Their exported surface is
stable and cheap to maintain.

## Alternatives considered

- **Freeze everything.** Rejected. It commits the project to maintaining compatibility for the
  composition layers as well as the primitives, which is exactly where the verification cost
  multiplies.
- **Split `authflow`, `webapp` and `oauth/providers` into separate modules now.** Rejected for
  v1. The packages either have no heavy dependencies to isolate (`authflow`, `webapp`) or a
  packaging change would be safer with the freeze already settled (`oauth/providers`). A label
  achieves the same compatibility boundary without a release-machinery change.
- **Deprecate a module.** Rejected. No module is unused or unmaintained; there is no replacement
  to point users to.
- **Change the existing "pre-1.0" stability wording to per-module promises immediately.**
  Rejected as a unilateral change. The proposal is recorded here; the wording is updated only
  once the maintainer accepts it.

## Consequences

- Consumers get an explicit list of what the v1 promise covers and what it does not. Packages
  labelled `experimental` remain supported and tested but may change without a major release.
- The frozen core is narrower than the full repository, which keeps the compatibility and
  maintenance burden focused on the modules that enforce security invariants.
- Experimental modules still need security maintenance; the label lowers the compatibility bar,
  not the quality bar.
- When the freeze lands, the release process should grow a technical guard: an API-compatibility
  diff over the `frozen-v1` packages that fails on an unintended break, with `experimental`
  packages excluded from the gate. That tooling is a follow-up, not part of this record.

## How this is applied today

- Each module's package documentation carries its proposed stability class, except `webapp`,
  whose existing v1 wording is left untouched pending the maintainer's decision.
- The README "Stability" section carries the class table; `SECURITY.md` points at the per-module
  guarantees in `docs/security-guarantees.md`.
- The v1 API-freeze review checklist and the deprecation policy live in `RELEASING.md`.
- Nothing in the code, options, defaults or behavior changes.
