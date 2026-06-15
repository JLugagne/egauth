# Milestone PRD: M1-v1.0

## Goal

Ship egauth v1.0.0 with a frozen, SemVer-stable public API, honest and build-enforced security-status
disclosure, no unbounded-growth footguns in the default in-memory stores, and enough documentation
and tooling for a new consumer to wire the full auth stack from the module proxy with no local
workspace.

## Success criteria

- Every exported symbol is either stable (v1 contract) or marked `// Experimental:`.
- The audit-status disclosure appears word-for-word in README, doc.go, llms.txt, and SECURITY.md,
  and a build-enforced test (`TestAuditStatusDisclosure`) fails if it is edited away.
- A clean `go get github.com/JLugagne/egauth` works from the module proxy without retracted versions.
- A runnable reference application in `examples/` wires identity + tokens + mfa + passkey + admin
  + audit over HTTP, building from the proxy with no local workspace.
- The in-memory stores for sessions, otp, and ratelimit have a bounded/self-evicting variant.
- An OpenTelemetry span adapter over `event.Sink` ships in `adapters/otel`.
- The Go-version support policy for v1.x is documented.
- Signed release tags and a documented release checklist are in place.
- The `sessions ↔ identity.WithAccountErasers` revocation fan-out is covered by an integration
  test proving real sessions become invalid on disable/delete.
- The `oauth/providers` module placement decision is recorded (keep in core or own module).
- `passkeytest.SoftAuthenticator` is exported so consumers can integration-test passkey flows.
- All `run:` commands in every merged task's DoD exit 0.

## Out of scope

- Asymmetric JWT signing (RS256/EdDSA) — deferred unless §1b mandates a public JWKS endpoint.
- Per-tenant JWKS endpoint helper — lands with §1b (backlog).
- Independent third-party human security audit — explicitly deferred post-v1.
- Performance benchmarks and Argon2 calibration helper — v1.x `[WANT]` items.
- Constant-time comparison lint checks — v1.x `[WANT]`.
- Sharded in-memory stores — v1.x `[WANT]` pending benchmark justification.
- Per-tenant OIDC (bring-your-own-SSO) — backlog feature (see feature-per-tenant-oidc.md).

## Integration contract

End-to-end scenarios that must pass when the milestone is complete:

1. **Audit disclosure durability**: `go test ./...` fails if the canonical audit-status sentence is
   edited out of any of README, doc.go, llms.txt, or SECURITY.md.
2. **Clean install**: `go get github.com/JLugagne/egauth` from a fresh module pulls a non-retracted
   version and the package builds.
3. **Reference app**: `go build ./examples/...` exits 0; the app wires all six auth concerns.
4. **Bounded store**: an in-memory sessions store with `maxSize=2` never holds more than 2 sessions
   (verified by test).
5. **OTel adapter**: `adapters/otel.NewSpanSink` wraps an OTEL tracer and emits spans (verified
   by unit test).
6. **Session revocation fan-out**: creating a live session, then calling
   `identity.DeleteAccount` (with a session-eraser wired via `WithAccountErasers`), then calling
   `sessions.ValidateSession` on the previously-live token returns `ErrSessionNotFound`.
7. **Passkey soft authenticator**: `passkeytest.NewSoftAuthenticator` returns a value usable in a
   table-driven passkey registration + login test without network calls.
8. **OAuth providers decision**: an ADR or architecture.md entry records the keep-in-core vs
   own-module decision with rationale.

## Constraints

- No breaking changes to any exported type or function in the `github.com/JLugagne/egauth` module.
- All new code must pass `go build ./...` and `go test ./...` (excluding integration tags).
- All modules (`adapters/otel`, `adapters/pgx`) must remain independently buildable.
- English only in all generated files.
- Security-critical auth SDK: correctness over speed.

## Risks

- `passkeytest` soft authenticator depends on internal WebAuthn wire format; a go-webauthn update
  could break it. Pin carefully and add a test that catches drift.
- Exporting `oauth/providers` as its own module is a multi-module restructure; if chosen, it must
  happen before v1 freeze to avoid a v2.
