# Epic: module-completeness

## Objective

Close the per-module feature gaps identified in road-to-v1.md §4 that block or should be resolved
before freezing the v1 API. Most modules are feature-complete; this epic targets the specific holes
that need to be either closed or explicitly declared out-of-scope with a recorded decision.

## Acceptance criteria

- `passkeytest.NewSoftAuthenticator` is exported and usable in consumer integration tests without
  any network calls; its registration + login flow is exercised by a test in the `passkeytest`
  package itself.
- An integration test in `test/` or the appropriate package proves the
  `sessions ↔ identity.WithAccountErasers` fan-out: disable/delete kills live sessions
  (a real `sessions.Service` is used, not a stub eraser).
- The `oauth/providers` placement decision (keep in core vs own module) is recorded in
  `architecture.md` with rationale, and `go build ./...` passes with no import-path changes.
- `go test ./...` and `go build ./...` both exit 0.

## Constraints

- No breaking changes to exported APIs.
- All new packages (`passkeytest`) must be inside the core module (`github.com/JLugagne/egauth`).
- The soft authenticator must NOT require a network (no real WebAuthn RP host needed).
- Integration tests that need the sessions service must use the in-memory backend only (no Postgres).

## Design decisions

### 2026-06-15 — Soft authenticator placement

Placed in `passkey/passkeytest/` (package `passkeytest`) to mirror the pattern of
`identity/servicetest`, `identity/storetest`, `mfa/storetest`, etc. The type is exported so
consumers can import it. It lives in the core module, not a separate module, because:
- It has no additional dependencies beyond what `passkey` itself imports.
- Separate module adds go.mod/go.sum churn with no isolation benefit.

### 2026-06-15 — oauth/providers placement decision

Keep `oauth/providers` in the core module (`github.com/JLugagne/egauth`) and freeze the 12
provider constructors as part of the v1 public API surface. Rationale: moving to a separate
module before v1 is significant restructuring risk; the 12 providers are already stable
(used by the reference app and docs); churn on provider constructors in v1.x can be absorbed by
additive changes (new constructors, not changed ones). Decision recorded in architecture.md.

## Open questions

- Tokens §4 item (asymmetric signing) is deferred until §1b decides public-JWKS vs HS256-only.
  This epic does not touch tokens/jwt.
