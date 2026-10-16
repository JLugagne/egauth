# ADR 0001 — v1 scope and stability classes

- **Status:** Proposed (maintainer decision pending), revised for v0.17
- **Date:** 2026-09-10, revised 2026-10-16
- **Deciders:** repository maintainer
- **Scope:** documentation only. This record changes no behavior and no API. It proposes which
  packages the v1 SemVer promise should cover and assigns each a stability class.

## Context

Tagging v1.0.0 turns every exported symbol in a frozen package into a long-lived compatibility
contract. v0.17 replaced the many-module toolkit with one composition object (`egauth.New`) and a
route builder (`Auth.Routes`), so the surface to freeze is much smaller than before: the
application-facing API is the root package, and everything that implements it sits in `internal/`.

A narrow, deep, independently tested surface under the SemVer promise is a more defensible
contract than a wide one. Packages that carry churn the project does not control, or that exist to
help tests, can ship as explicitly experimental.

## Stability classes

| Class | Promise |
|---|---|
| `frozen-v1` | The exported API is intended to remain backward-compatible for the life of v1. Breaking changes require a new major version. |
| `experimental` | No SemVer guarantee. The API may change or be removed in any release. The package is maintained but outside the compatibility contract. |
| `split` | Recommended to move to its own Go module so it can version independently of the core. |

## Recommendation

| Package | Why | Class |
|---|---|---|
| `egauth` | The application-facing API: `New`, `Config`, `Auth`, `Routes`, `Principal`, facades, delivery messages | `frozen-v1` |
| `principal`, `event`, `kek`, `signing` | Small value and seam packages that applications and adapters import | `frozen-v1` |
| `passwords` and its references | Hashing, policy and breach-check seams with Argon2id references | `frozen-v1` |
| `store/*` contracts | Implemented by third-party backends; changes need new methods, which breaks implementers, so they are frozen with their suites | `frozen-v1` |
| `memstore`, `adapters/pgx`, `adapters/otel` | Reference backends and sinks against the frozen contracts | `frozen-v1` |
| `federation` | Provider spec and secret types | `frozen-v1` |
| `federation/providers` | Provider endpoints, scopes and claims change on the providers' schedule, not the project's | `experimental` (future `split`) |
| `egauthtest`, `webauthntest` | Test doubles; they follow the library rather than lead it | `experimental` |

Everything under `internal/` and `tools/` is outside the contract by construction.

## Notes on the notable calls

**The store contracts are frozen.** A custom backend implements them and runs the shared suites,
so adding a method breaks every implementer. The contracts therefore change only in a major
version, and the suites ship with them.

**`federation/providers` is experimental.** Each built-in encodes provider-specific endpoints and
claims that change when the provider decides. Freezing them would turn every upstream change into a
potential major version. The provider spec and the protocol code stay frozen; the built-ins are
convenience constructors.

## Alternatives considered

- **Freeze everything.** Rejected. It commits the project to compatibility for the test doubles and
  the provider presets, where churn is highest.
- **Split `federation/providers` into its own module now.** Rejected for v1. A label gives the same
  compatibility boundary without a change to the release machinery.

## Consequences

- Consumers get an explicit list of what the v1 promise covers and what it does not. Experimental
  packages remain supported and tested but may change without a major release.
- The release process should grow a technical guard: an API-compatibility diff over the `frozen-v1`
  packages that fails on an unintended break. That tooling is a follow-up.

## How this is applied today

- Package documentation carries the proposed class. The pre-1.0 wording in the README stays until
  the maintainer accepts this proposal.
