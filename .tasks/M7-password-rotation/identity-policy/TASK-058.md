---
id: TASK-058
title: SetTemporaryPassword and AdminCreateUser service methods
description: Add Service.SetTemporaryPassword(ctx,tenant,userID,tempPassword) and Service.AdminCreateUser(ctx,tenant,email,tempPassword); both set the password hash with MustChangePassword=true and PasswordChangedAt=now. Run account erasers where existing sessions must be revoked.
milestone: M7-password-rotation
epic: identity-policy
status: done
priority: normal
type: feature
blocked_by: [TASK-055]
branch: feat/m7-password-rotation
---

## Actions

- [x] Add `SetTemporaryPassword` and `AdminCreateUser` to the `Service` interface in identity/service.go
- [x] Implement `service.SetTemporaryPassword`: requirePasswordDeps, policy.Verify, hash, UpdateIdentityPassword(mustChange=true), run erasers
- [x] Implement `service.AdminCreateUser`: normalize email, CreateUser, hash, AddIdentity(MustChangePassword=true, PasswordChangedAt=now), compensate on AddIdentity failure
- [x] Add `SetTemporaryPasswordFunc` / `AdminCreateUserFunc` to `MockService` in identity/servicetest/contract.go with method impls
- [x] Add `SetTemporaryPassword` / `AdminCreateUser` delegating wrappers to `SingleTenant` in identity/singletenant.go
- [x] Write tests: `TestSetTemporaryPassword_*` and `TestAdminCreateUser_*` in identity/admin_provisioning_test.go
- [x] Validate: go build + go test ./identity/... green

## Definition of Done

- [x] `Service` interface has both methods | run: grep -n 'SetTemporaryPassword\|AdminCreateUser' identity/service.go
- [x] `service` struct implements both methods | run: grep -n 'func (s \*service) SetTemporaryPassword\|func (s \*service) AdminCreateUser' identity/service.go
- [x] `MockService` implements both (compile-time check `var _ identity.Service = (*MockService)(nil)` already present) | run: grep -n 'SetTemporaryPassword\|AdminCreateUser' identity/servicetest/contract.go
- [x] `SingleTenant` exposes both methods | run: grep -n 'SetTemporaryPassword\|AdminCreateUser' identity/singletenant.go
- [x] `TestSetTemporaryPassword_SetsFlag` passes (PasswordChangeRequired true after call) | run: go test -run TestSetTemporaryPassword ./identity/...
- [x] `TestAdminCreateUser_CreatesUserWithFlag` passes (user returned, flag set) | run: go test -run TestAdminCreateUser ./identity/...
- [x] Full suite green | run: go test ./identity/...

## Discussion

### 2026-06-19 — Design choices

**SetTemporaryPassword eraser pattern**: mirrors ChangePassword/ResetPassword exactly — collect all eraser errors via errors.Join; a single failing eraser does not suppress others.

**AdminCreateUser orphan compensation**: mirrors Register — if AddIdentity fails after CreateUser succeeds, we soft-delete the orphaned user (best-effort) to free the email slot.

**No event for AdminCreateUser**: Register emits UserRegistered; AdminCreateUser is admin-provisioning, not self-registration. Emitting UserRegistered would be misleading. A dedicated AdminUserProvisioned event is out of scope for M7; no event is emitted to keep it consistent with the existing pattern (only the caller knows the context).

**SetTemporaryPassword policy check**: tempPassword IS run through policy.Verify so admins cannot set a password that fails the tenant's policy (consistency with ChangePassword/ResetPassword).

### 2026-06-19 — Ready for review

DoD verification commands:
- `grep -n 'SetTemporaryPassword\|AdminCreateUser' identity/service.go` — interface + impl
- `grep -n 'SetTemporaryPassword\|AdminCreateUser' identity/servicetest/contract.go` — mock
- `grep -n 'SetTemporaryPassword\|AdminCreateUser' identity/singletenant.go` — single-tenant wrapper
- `go test -run TestSetTemporaryPassword ./identity/...` — flag test
- `go test -run TestAdminCreateUser ./identity/...` — admin create test
- `go test ./identity/...` — full suite

### 2026-06-19 — Closed (reviewer audit)

Independently re-verified by a separate reviewer (re-derived, did not trust checkboxes). `task.sh check` exits 0.

Per-DoD verification:
- `Service` interface has both methods — verified by reading identity/service.go:229-231 (both declared in the interface block at line 85), not only the struct impl.
- `service` struct implements both — verified by reading the bodies at identity/service.go:1317 (SetTemporaryPassword) and 1352 (AdminCreateUser).
- `MockService` implements both — verified by grep (contract.go:194,201) plus the compile-time assertion `var _ identity.Service = (*MockService)(nil)` at contract.go:80, which the green build proves holds.
- `SingleTenant` exposes both — verified by reading singletenant.go:146 and 151 delegating to the empty tenant.
- `TestSetTemporaryPassword_*` and `TestAdminCreateUser_*` — verified by re-running the full identity suite via go-surgeon test_run: 271 passed, 0 failed across 4 packages.
- Full suite green + build (incl. tests) clean — verified by go-surgeon build_check (exit 0) and test_run.

Security audit (flag-drop / gate-bypass):
- SetTemporaryPassword passes mustChange=true to UpdateIdentityPassword (service.go:1328); the memory store persists it (store.go:281) and the end-to-end TestSetTemporaryPassword_SetsFlag confirms PasswordChangeRequired flips to true. Erasers run post-write to revoke existing sessions, errors collected via errors.Join, ctx cancellation honored — mirrors ResetPassword exactly.
- AdminCreateUser sets MustChangePassword=true and PasswordChangedAt=now on the Identity (service.go:1378-1379); the end-to-end TestAdminCreateUser_CreatesUserWithFlag confirms the flag round-trips through the real store, and TestAdminCreateUser_PasswordChangedAtIsStamped confirms the timestamp. No erasers (fresh account, correct).
- Both methods guard with requirePasswordDeps + policy.Verify before any store write; tests confirm no write on policy/dep rejection. AddIdentity-failure compensation (soft-delete orphan) mirrors Register and is test-covered.
- No event emitted by AdminCreateUser (documented design choice). Delivers SC-3.

Commit fa5786e / 735a2dc on feat/m7-password-rotation, TASK-058-prefixed, no co-author trailer.
