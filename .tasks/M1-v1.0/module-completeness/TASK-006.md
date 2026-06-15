---
id: TASK-006
title: Module completeness & feature gaps
description: Close the per-module feature gaps from road-to-v1.md §4 — export the passkey soft authenticator, add a real sessions-revocation integration test, and record the oauth/providers module placement decision.
milestone: M1-v1.0
epic: module-completeness
status: done
priority: normal
type: feature
blocked_by: []
branch: "task/TASK-006-module-completeness"
---

## Actions

- [x] Export `softAuthenticator` as `passkeytest.SoftAuthenticator` in `passkey/passkeytest/`
- [x] Add a self-test in `passkey/passkeytest/` exercising registration + login with the exported authenticator
- [x] Add an integration test in `test/` (or `identity/`) proving sessions are killed when `identity.DeleteAccount` is called with a real session eraser wired via `WithAccountErasers`
- [x] Record the `oauth/providers` placement decision (keep in core) in `.llms/architecture.md`
- [x] Verify `go build ./...` and `go test ./...` both pass

## Definition of Done

- [x] `passkeytest.NewSoftAuthenticator` is exported and compiles | run: go build ./passkey/passkeytest/...
- [x] The passkeytest self-test passes | run: go test ./passkey/passkeytest/...
- [x] Integration test `TestDeleteAccount_RevokesLiveSessions` passes | run: go test ./test/... -run TestDeleteAccount_RevokesLiveSessions
- [x] `grep -q "oauth/providers" .llms/architecture.md` exits 0 (placement decision recorded) | run: grep -q "oauth/providers" .llms/architecture.md
- [x] Full build passes | run: go build ./...
- [x] Full test suite passes | run: go test ./...
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-15 — Scope from road-to-v1.md §4

Items addressed by this task:
- **passkey [WANT]**: export `softAuthenticator` (in `passkey/authenticator_test.go`) as a public
  `passkeytest.SoftAuthenticator` in a new `passkey/passkeytest` package. The existing 200-line
  test helper re-implements ES256 + WebAuthn wire format; consumers integration-testing passkey
  flows currently have to copy it verbatim.
- **sessions [WANT]**: the existing `TestDeleteAccount_RunsErasersThenDeletes` uses stub lambdas,
  not a real `sessions.Service`. Adding a test with a real in-memory sessions service proves the
  full fan-out: sessions.ValidateSession returns ErrSessionNotFound after DeleteAccount.
- **oauth [BLOCK-IF-SHIPPED]**: decide before v1 freeze. Decision: keep in core. Recorded in
  architecture.md.
- **otp/identity [WANT]**: existing tests already cover enumeration-safe invariants
  (`TestIssueHandler_UnknownSubjectStillReturns204`, `TestVerifyHandler_CollapsesAllFailures`,
  `TestLoginHandler_AccountDisabled_MatchesLockedResponse`). No new code needed.
- **tokens [BLOCK-if-public-JWKS]**: deferred — tied to §1b per-tenant JWKS decision.

Items NOT in scope:
- Tokens asymmetric signing — deferred until §1b.
- Per-tenant JWKS endpoint — deferred until §1b.

### 2026-06-15 — Ready for review

All DoD items verified:

- `go build ./passkey/passkeytest/...` exits 0: `passkeytest.SoftAuthenticator` is exported in
  `passkey/passkeytest/authenticator.go` (258 lines). Public API: `NewSoftAuthenticator`,
  `RegistrationRequest`, `RegistrationRequestWithFlags`, `LoginRequest`, `LoginRequestAtCount`,
  `LoginRequestWithFlags`, `UserHandleOf`, plus exported flag constants `FlagUP/UV/AT/BE/BS`.

- `go test ./passkey/passkeytest/...` exits 0: 3 tests pass
  (`TestSoftAuthenticator_RegistrationAndLogin`, `TestSoftAuthenticator_MultipleLogins`,
  `TestSoftAuthenticator_BackupFlags`). These exercise the full registration + login round-trip
  against a real `passkey.Service` with in-memory stores, no network.

- `go test ./test/... -run TestDeleteAccount_RevokesLiveSessions` exits 0: integration test
  in `test/sessions_revocation_integration_test.go` wires a real `sessions.Service` as an
  `AccountEraser` and confirms that after `DeleteAccount`, `ValidateSession` returns
  `ErrSessionNotFound`. A second test (`TestDisableAccount_WithSessionRevocation`) covers the
  caller-driven disable+revoke pattern (since `DisableUser` has no eraser hook).

- `grep -q "oauth/providers" .llms/architecture.md` exits 0: the "Module placement decisions"
  section in `.llms/architecture.md` documents the keep-in-core decision with rationale.

- `go build ./...` exits 0: 988 tests pass across 40 packages, zero failures.
