# Security guarantees by area

This page summarises, area by area, what `egauth` guarantees, the mechanism that holds the
guarantee, and what the application remains responsible for. [SECURITY.md](../SECURITY.md) is the
source of record for the secret-handling model and the mechanisms behind these statements.
[CONTRIBUTING.md](../CONTRIBUTING.md) lists the CI guards (`G1` to `G29`) by number.

Stability classes are in [ADR 0001](adr/0001-v1-scope-and-stability-classes.md).

## Composition

| Guarantee | Mechanism | Application responsibility |
|---|---|---|
| A broken configuration never serves a request | `egauth.New` validates every tag and returns all problems joined (G4, G5) | handle the error from `New` |
| Policy is owned once | no exported handler, option or cookie constructor (G1, G2, G6) | none |
| Weakening a default is explicit | `egauth.InsecureOptOuts`, each with a reason, listed by `Auth.Posture` (G7) | keep it empty in production |
| Undeclared routes do not exist | `Auth.Routes`; every other request is 404 (G19) | declare routes through it |

## Sessions and revocation

| Guarantee | Mechanism | Application responsibility |
|---|---|---|
| A login proves what it proves, no more | sealed `principal.SessionAttrs`, replayed and only strengthened (G6, G8, G21) | none |
| Enrolled users cannot skip a second factor | enrollment read from stored state at every primary login (G23) | none |
| Revocation does not rely on a callback | per-subject security epoch bumped with the mutation; fail-closed polling (G21) | none |
| Refresh theft is detected | single-use rotation, family revoked on replay outside the grace window | none |
| Sensitive actions need a fresh, multi-factor session | the preamble and every facade | none |

## Requests

| Guarantee | Mechanism | Application responsibility |
|---|---|---|
| Cross-site requests are refused | fetch metadata, `Origin` and `Referer` checks in `internal/csrf` (G22) | none |
| Cookies are scoped and protected | `__Host-` prefix, `Secure`, `HttpOnly`, three closed classes (G6) | none |
| Client address is derived once | `internal/clientaddr` under the configured proxy policy | state the proxy policy truthfully |
| Rate limits apply to authentication endpoints | library budgets from storage, checked by a startup probe (G22) | share durable storage across replicas |
| Request bodies are capped | the preamble | none |
| Redirect targets are validated | one validator, fuzzed (G22) | list pages and origins in the configuration |
| Identifiers are not enumerable | uniform answers and decoy hashing (G28) | none |

## Credentials

| Guarantee | Mechanism | Application responsibility |
|---|---|---|
| Passwords are hashed with a memory-hard function | Argon2id, NFKC floor, optional breach check | supply a breach checker if wanted |
| Opaque tokens are stored as hashes | SHA-256 digests as store keys | none |
| Secrets at rest are bound to their context | `kek.KEK` with mandatory associated data | keep the KEK in a secret store |
| Passkeys are discoverable and user-verified | `internal/passkeysvc`, `webauthntest` (G24) | none |
| Federated identities do not take over accounts | no automatic link; verified email on registration (G23) | none |
| Outbound requests cannot reach private networks | one client in `internal/outbound` (G6) | none |

## Administration

| Guarantee | Mechanism | Application responsibility |
|---|---|---|
| Authorization is inside the facade | `Auth.Accounts`, `Auth.Tenants`, `Auth.APIKeys` check the caller (G22) | pass the caller from the principal |
| Background work is explicit | `Auth.System`, refused inside a request | supply a reason |
| API keys never reach session routes | `ProtectAPI` and `Protect` are disjoint (G22) | declare kinds |

## Observability

| Guarantee | Mechanism | Application responsibility |
|---|---|---|
| Events carry no secrets | declared attribute sensitivities (G10) | choose a sink |
| Delivery messages redact credentials in `fmt` and `slog` | `LogValue`, `String`, `GoString` | keep JSON-queued messages protected |

Residual risks and accepted trade-offs are listed in [AUDIT.md](../AUDIT.md) and
[SECURITY.md](../SECURITY.md).
