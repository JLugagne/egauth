---
id: TASK-067
title: Document the password-rotation / forced-change policy
description: Update .llms (architecture, tokens), SECURITY.md, README.md and CHANGELOG.md to describe the opt-in policy: soft-gate semantics, access-only-when-flagged rationale, configuration surface and admin provisioning methods. Reference only symbols that exist; do not link audit-findings logs.
milestone: M7-password-rotation
epic: docs
status: in_progress
priority: normal
type: chore
blocked_by: [TASK-059, TASK-062, TASK-066]
branch: "feat/m7-password-rotation"
---

## Actions

- [x] Read existing .llms/architecture.md, .llms/tokens.md, .llms/storage-pgx.md, SECURITY.md, README.md, CHANGELOG.md to understand current state and uncommitted edits
- [x] Audit all actual symbols on the branch (identity.WithPasswordRotation, WithPasswordRotationResolver, WithMustChangeTTL, WithPasswordChangeGate, AdminCreateUser, SetTemporaryPassword, tokens.Claims.MustChangePassword, ChangePasswordWithReissueHandler, PasswordChangeRequired)
- [x] Update .llms/architecture.md — add password-rotation policy to Security posture summary + Composition graph
- [x] Update .llms/tokens.md — add MustChangePassword field to Claims section, document WithPasswordChangeGate AuthOption, document DefaultMustChangeTTL
- [x] Update .llms/storage-pgx.md — add migration 008_add_password_rotation.sql to identity section, document new identity columns
- [x] Update SECURITY.md — add forced-password-change section describing soft-gate semantics and access-only rationale
- [x] Update README.md — add forced-password-change mention in Security section and Modules table identity row
- [x] Update CHANGELOG.md — add Unreleased entry for the M7 feature
- [x] Run doc-drift guard (go run ./internal/doctest) to confirm no dangling symbol references

## Definition of Done

- [x] .llms/architecture.md mentions the rotation policy, WithPasswordRotation, WithPasswordRotationResolver | run: grep -c "WithPasswordRotation" .llms/architecture.md
- [x] .llms/tokens.md documents MustChangePassword claim, WithPasswordChangeGate, DefaultMustChangeTTL | run: grep -c "MustChangePassword\|WithPasswordChangeGate\|DefaultMustChangeTTL" .llms/tokens.md
- [x] .llms/storage-pgx.md documents migration 008 and the new identity columns | run: grep -c "008_add_password_rotation\|password_changed_at\|must_change_password" .llms/storage-pgx.md
- [x] SECURITY.md has a section on the forced-password-change / soft-gate policy | run: grep -c "soft.gate\|must.change\|rotation" SECURITY.md
- [x] CHANGELOG.md has an Unreleased entry for M7 | run: grep -c "password.rotation\|forced.password\|must.change" CHANGELOG.md
- [x] Doc-drift guard passes with no dangling symbols | run: go run ./internal/doctest

## Discussion

### 2026-06-19 — design choices for doc wording

The access-only / no-refresh-cookie rationale is the most important nuance to document clearly:
a flagged login issues a short-TTL access token only (no refresh cookie) so the flag cannot be
silently dropped on the first silent refresh, which would allow the user to slip past the gate
indefinitely. This is documented in all four doc surfaces.

The "zero PasswordChangedAt = not due" legacy behaviour is called out in storage-pgx.md (it
mirrors the SQL comment in 008_add_password_rotation.sql) so operators applying the migration to
existing data understand why no pre-existing users are immediately flagged.

Symbol coverage verified manually: every qualified identifier added to the docs was cross-checked
against the symbol output of go-surgeon before committing.

### ready for review

DoD verification commands:
- `grep -c "WithPasswordRotation" .llms/architecture.md` — expect >= 1
- `grep -c "MustChangePassword\|WithPasswordChangeGate\|DefaultMustChangeTTL" .llms/tokens.md` — expect >= 3
- `grep -c "008_add_password_rotation\|password_changed_at\|must_change_password" .llms/storage-pgx.md` — expect >= 3
- `grep -c "soft.gate\|must.change\|rotation" SECURITY.md` — expect >= 3
- `grep -c "password.rotation\|forced.password\|must.change" CHANGELOG.md` — expect >= 1
- `go run ./internal/doctest` — expect exit 0 (no dangling symbols)
