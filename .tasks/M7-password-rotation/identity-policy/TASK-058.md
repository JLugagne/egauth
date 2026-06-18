---
id: TASK-058
title: SetTemporaryPassword and AdminCreateUser service methods
description: Add Service.SetTemporaryPassword(ctx,tenant,userID,tempPassword) and Service.AdminCreateUser(ctx,tenant,email,tempPassword); both set the password hash with MustChangePassword=true and PasswordChangedAt=now. Run account erasers where existing sessions must be revoked.
milestone: M7-password-rotation
epic: identity-policy
status: in_progress
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
