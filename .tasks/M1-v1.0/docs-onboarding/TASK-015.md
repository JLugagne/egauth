---
id: TASK-015
title: Runnable reference application (identity+tokens+mfa+passkey+admin+audit over HTTP)
description: One runnable reference application wiring a real multi-module stack — identity + tokens(custom claims) + mfa + passkey + admin + audit — over HTTP, building from the proxy with no local workspace. Split off from TASK-007 (#25), whose go-get/Example-test items are already done.
milestone: M1-v1.0
epic: docs-onboarding
status: in_progress
priority: normal
type: feature
blocked_by: []
branch: "task/TASK-015-runnable-ref-app"
---

## Actions

- [x] Create a runnable reference app (under `examples/` or a linked repo) wiring identity + tokens(custom claims) + mfa + passkey + admin + audit over HTTP
- [x] Ensure it builds from the module proxy with no local `go.work` workspace
- [x] Link the reference app from README and llms.txt

## Definition of Done

- [x] The reference app builds | run: go build ./examples/...
- [x] It wires all six concerns (identity, tokens+custom claims, mfa, passkey, admin, audit) — verified by reading main and an Example/smoke test
- [x] README and llms.txt link to the reference app (verified by grep) | run: grep -rqi "example" README.md llms.txt
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-13 — Split off from TASK-007 (GitHub issue #25, v1 §5)
Source: https://github.com/JLugagne/egauth/issues/25 (the runnable reference-app [BLOCK] bullet).
TASK-007's clean-`go get` story and per-module Example tests are verified done; what remains is a single full reference *application*. Today only smaller Example tests exist (webapp/example_test.go, identity/example_test.go) and there is no `examples/` directory. The `go build ./examples/...` DoD assumes the app lands under `examples/`; adjust the run: target if it ships as a linked repo.

### 2026-06-14 — Implementation

Found `examples/fullstack/main.go` and `examples/fullstack/smoke_test.go` already committed on this branch (409 and 214 lines respectively). The app was already wiring all six concerns correctly. One compile error existed: `ExampleBuildServer` in the smoke test referred to the exported name `BuildServer`, but the function was declared as `buildServer` (unexported). Renamed `buildServer` -> `BuildServer` in both files (main.go and smoke_test.go) to fix the build.

Go-surgeon MCP cannot access worktree-only files (it runs against the main checkout at a fixed path, not the worktree). Used Edit as a fallback for the rename, which is safe here since the rename is a pure textual substitution with no structural ambiguity. Line counts confirmed unchanged after all edits (409 and 214 lines).

Added "Reference application" section to README.md (before the Documentation section) and a bullet to the "Start here" section of llms.txt pointing to `examples/fullstack`.

Build: `go build ./examples/...` exits 0. Tests: 5 pass (TestBuildServer, TestFullStackRegisterLoginMe, TestFullStackMFAEnrollConfirm, TestFullStackPasskeyRoutesMounted, ExampleBuildServer).

### 2026-06-14 — Ready for review

All DoD items verified:
- `go build ./examples/...` exits 0 (confirmed in shell).
- All six concerns wired in `examples/fullstack/main.go`: identity (RegisterHandler/LoginHandler), tokens+custom claims (AppClaims with Role, jwt.New[AppClaims]), mfa (EnrollHandler/ConfirmHandler/VerifyHandler), passkey (BeginRegistrationHandler/FinishRegistrationHandler/BeginLoginHandler/FinishLoginHandler), admin (DisableUser/EnableUser/UnlockMFA behind RequireAuth with role check), audit (event.NewSlogSink wired to all services). Smoke tests exercise all layers.
- `grep -rqi "example" README.md llms.txt` exits 0 (confirmed).
- All Actions and DoD checkboxes are `[x]`.
