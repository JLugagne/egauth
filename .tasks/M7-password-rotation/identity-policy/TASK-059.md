---
id: TASK-059
title: Integration-verify: identity-side forced-change end-to-end
description: Prove the identity side end-to-end against the memory store: admin-provisioned and aged-past-maxAge credentials report PasswordChangeRequired=true; a per-tenant opt-out reports false (IC-3); a change/reset stamps PasswordChangedAt and clears the flag (IC-2, SC-6).
milestone: M7-password-rotation
epic: identity-policy
status: done
priority: high
type: integration-verify
verifies: [TASK-055, TASK-056, TASK-057, TASK-058]
blocked_by: [TASK-055, TASK-056, TASK-057, TASK-058]
branch: feat/m7-password-rotation
---

## Actions

- [x] Add an end-to-end test file `identity/password_rotation_integration_test.go` wiring a real `identity.NewService` over the in-memory `identitymemory.NewStore()` with a mutable, controllable clock helper.
- [x] (IC-2 / SC-6) Scenario: rotation-enabled user whose password was stamped past maxAge reports `PasswordChangeRequired=true`; after `ChangePassword` the flag clears, `PasswordChangedAt` is re-stamped to the new clock, and the query reports false.
- [x] (SC-6) Scenario: same as above but cleared via `ResetPassword` (token flow) instead of `ChangePassword`.
- [x] (IC-3) Scenario: tenant A `WithPasswordRotation(30d)` and tenant B opted out via `WithPasswordRotationResolver` -> B's aged user reports false while A's aged user reports true.
- [x] (SC-3) Scenario: `AdminCreateUser` and `SetTemporaryPassword` users report `PasswordChangeRequired=true`, and `ChangePassword`/`ResetPassword` clears the admin/temp flag.

## Definition of Done

- [x] (IC-2/SC-6) Aged-then-changed scenario passes | run: go test ./identity/ -run TestRotationIntegration_AgedThenChangeClears -count=1
- [x] (SC-6) Aged-then-reset scenario passes | run: go test ./identity/ -run TestRotationIntegration_AgedThenResetClears -count=1
- [x] (IC-3) Per-tenant opt-out scenario passes | run: go test ./identity/ -run TestRotationIntegration_PerTenantOptOut -count=1
- [x] (SC-3) Admin/temp provisioning scenarios pass | run: go test ./identity/ -run TestRotationIntegration_AdminProvisioned -count=1
- [x] The whole identity suite stays green | run: go test ./identity/ -count=1

## Discussion

### 2026-06-19 — Test design

- New file `identity/password_rotation_integration_test.go` wires the real `identity.NewService`
  over `identitymemory.NewStore()` (not a MockStore), so the `PasswordChangedAt` stamp and
  `MustChangePassword` flag genuinely round-trip through `UpdateIdentityPassword` and are read
  back by `PasswordChangeRequired`.
- A `movableClock` (mutable `time.Time` behind a `now()` closure passed to `WithClock`) lets a
  single service instance age a credential past `maxAge` without rebuilding the service.
- Important wrinkle exercised honestly: `Register` does NOT stamp `PasswordChangedAt` (it stays
  zero, which is the documented "legacy = not due" case). To get a datable aged credential the
  tests perform one `ChangePassword` to stamp a concrete timestamp, then advance the clock.
- IC-3 uses one service with a resolver that returns `(maxAge, true)` for tenant A and
  `(0, false)` for tenant B, proving the per-tenant resolver fully overrides the global default.
- SC-3 uses a service with rotation OFF (no `WithPasswordRotation`) to prove the explicit flag
  from `AdminCreateUser`/`SetTemporaryPassword` alone drives the requirement, independent of age,
  and that `ChangePassword`/`ResetPassword` clears it.

### 2026-06-19 — Ready for review

All DoD items verified locally with go-surgeon test_run (sandbox-disabled reviewer can re-run via
the `| run:` commands):
- IC-2/SC-6 ChangePassword path: `go test ./identity/ -run TestRotationIntegration_AgedThenChangeClears -count=1` — pass.
- SC-6 ResetPassword path: `go test ./identity/ -run TestRotationIntegration_AgedThenResetClears -count=1` — pass.
- IC-3 per-tenant opt-out: `go test ./identity/ -run TestRotationIntegration_PerTenantOptOut -count=1` — pass.
- SC-3 admin/temp provisioning: `go test ./identity/ -run TestRotationIntegration_AdminProvisioned -count=1` — pass.
- Whole suite: `go test ./identity/ -count=1` — 262 passed, 0 failed.
No production code changed; this task only adds tests. No underlying bug found — all scenarios pass
against the implementations from TASK-055..058.

### 2026-06-19 — Closed (reviewer audit)

Independently re-verified by a separate reviewer (re-derived everything, did not trust the
checkboxes). `task.sh check` exits 0 — all 5 `| run:` commands PASS.

Test is integration-genuine, not mock-driven: `rotationTestService` wires the real
`identity.NewService` over the real `identitymemory.NewStore()`; assertions read
`PasswordChangedAt` straight from the store via `FindIdentitiesByUserID`, so the stamp + flag
round-trip through the actual `UpdateIdentityPassword` write path (memory/store.go:280-281).

Per-DoD verification:
- (IC-2/SC-6) `TestRotationIntegration_AgedThenChangeClears` — re-run green via go-surgeon
  test_run. Premise sound: `Register` leaves `PasswordChangedAt` zero (service.go:425-430), the
  documented "legacy = not due" case (PasswordChangeRequired short-circuit at service.go:1305);
  the first ChangePassword establishes a datable stamp. Asserts due after aging, then `clock.now()`
  re-stamp and not-due after the change.
- (SC-6) `TestRotationIntegration_AgedThenResetClears` — re-run green. Exercises the real reset
  token flow (RequestPasswordReset -> ResetPassword); ResetPassword calls UpdateIdentityPassword
  with `s.now(), mustChange=false` (service.go:660).
- (IC-3) `TestRotationIntegration_PerTenantOptOut` — re-run green. Genuinely drives the
  resolver-override branch (service.go:1296-1298): tenant-b resolver returns (0,false) -> not due;
  tenant-a returns (maxAge,true) -> due.
- (SC-3) `TestRotationIntegration_AdminProvisioned` (both subtests) — re-run green. Rotation OFF,
  so it proves the explicit `MustChangePassword` flag alone drives the requirement via the
  short-circuit at service.go:1287, independent of age; cleared by ChangePassword (admin) and
  ResetPassword (temp), both passing mustChange=false.
- Whole identity suite — re-run via go-surgeon test_run: 262 passed, 0 failed.

Security audit (flag-drop / gate-bypass, identity side): the must-change flag is set only by
provisioning (AdminCreateUser service.go:1378, SetTemporaryPassword service.go:1328) and cleared
only through the single legitimate write path with mustChange=false (ChangePassword service.go:728,
ResetPassword service.go:660). No identity-side path silently drops the flag. The JWT-claim and
middleware gate are out of this task's scope.

Commit cb674cf on feat/m7-password-rotation, TASK-059-prefixed, no co-author trailer. (The commit
also carries a benign TASK-058.md edit — the prior reviewer's closing entry for the already-done
TASK-058, not a regression.)
