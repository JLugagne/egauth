# Definition of Done

The `## Definition of Done` section is what separates "code was written" from "the feature works." This file explains how to write DoD items that actually catch incomplete work.

**Prerequisites:** read `references/structure.md` for the section format.

## The core principle

**Every DoD item must be mechanically verifiable.** Someone (or some script) must be able to look at the codebase and the repo state and say "yes this passes" or "no this fails" without needing judgment. If an item requires interpretation, it's not a DoD — it's a hope.

The acid test: could a CI script or a reviewer LLM check this item? If no, rewrite it.

## Why this matters

Small autonomous LLMs (and tired humans) tend to mark tasks `done` as soon as the code compiles. They write the implementation, see no errors, mark the checkbox, move on. The integration that was supposed to wire the new code into the rest of the system gets skipped — silently. The task looks done; the feature is broken.

DoD items written in mechanical form prevent this. "Code compiles" can't be a DoD because it's the floor, not the ceiling. "Function X is called from Y" is a DoD because it requires the integration to actually exist.

## Good DoD patterns

### Test passes

The strongest form. Names a specific test.

```markdown
- [ ] Test `TestRefreshTokenRotation` passes
- [ ] Test `TestExpiredRefreshReturns401` passes
- [ ] `go test ./internal/auth/...` passes with zero failures
```

If the test doesn't exist yet, writing it is part of the task's Actions.

### Wired integration

Catches the most common failure: code exists but is never called.

```markdown
- [ ] `RefreshHandler.Refresh` is called from `AuthMiddleware.HandleExpiry`
  (verified by `grep -r "RefreshHandler.Refresh" internal/`)
- [ ] `InvalidateCache` is called in `CreateDocument`, `UpdateDocument`, and `DeleteDocument`
  (verified by grep returning 3+ matches)
- [ ] The `/api/v1/auth/refresh` route is registered in `router.SetupRoutes`
```

Use grep patterns when possible — they're trivially checkable.

### End-to-end scenario

A concrete observable behavior. Given → when → then.

```markdown
- [ ] Given an expired access token + valid refresh token in cookies,
  when the client calls `/api/me`,
  then the response is 200 with the user JSON,
  and the response sets a new access token cookie,
  and the old refresh token is rotated.
- [ ] Given a document with status=draft, when status is updated to=proposed,
  then a row appears in `audit_logs` with action=notification_dispatched.
```

The format is verbose on purpose. A vague "refresh works" doesn't catch the case where the cookie is forgotten or the rotation never happens.

### Migration applied

For database changes.

```markdown
- [ ] Migration `003_add_refresh_tokens.sql` applied,
  table `refresh_tokens` exists with columns `id, user_id, token_hash, expires_at, rotated_from`
- [ ] `\d refresh_tokens` in psql shows the index on `token_hash`
```

### Failure case covered

For anything user-facing or with state.

```markdown
- [ ] When the IdP returns 503, the auth handler responds 502 (not 500)
  and logs the upstream status code
- [ ] When two clients refresh the same token concurrently, exactly one
  succeeds; the other gets 401 (verified by `TestConcurrentRefresh`)
```

### No regression

When work touches shared code.

```markdown
- [ ] All previously-passing tests still pass (`go test ./...` exit code 0)
- [ ] Existing migration sequence still runs cleanly from scratch
  (verified by `make db-reset` succeeding)
```

### The mandatory final item

Every feature/integration-verify task ends with:

```markdown
- [ ] All Actions checkboxes above are `[x]`
```

This is the safety net. Even if every other DoD passes, an unchecked Action means scope was abandoned silently.

## Bad DoD patterns

These look like DoD but aren't checkable. **Do not use them.**

| Bad                                  | Why it's bad                                          | Replace with                                       |
| ------------------------------------ | ----------------------------------------------------- | -------------------------------------------------- |
| Code looks clean                     | Subjective                                            | A specific test or grep pattern                    |
| No obvious bugs                      | Negative + subjective                                 | A concrete failure case test                       |
| Tests are added                      | "Added" ≠ "passing"                                   | `Test X passes` (name the test)                    |
| Function works                       | What does "works" mean?                               | An end-to-end scenario                             |
| Integration is wired                 | "Wired" is fuzzy                                      | `X is called from Y (verified by grep)`            |
| Code review approved                 | Approval ≠ correctness                                | The specific things the reviewer would check       |
| Documented                           | Documented where? How much?                           | "README section X exists" or "godoc for Y exists"  |
| Performance is acceptable            | Acceptable to whom?                                   | "Endpoint responds in <500ms on benchmark X"       |
| Doesn't break anything               | Impossible to verify by inspection                    | "All previously-passing tests still pass"          |

## DoD for `integration-verify` tasks

These tasks exist specifically to prove that multiple previously-completed tasks work together. Their DoD is the centerpiece of the task, not a sidebar.

Structure:

```markdown
## Actions

- [ ] Write integration test file `internal/auth/integration_test.go`
- [ ] Set up testcontainers for Postgres
- [ ] Run the scenarios

## Definition of Done

- [ ] Scenario A passes: <full scenario with Given/When/Then>
- [ ] Scenario B passes: <...>
- [ ] Scenario C passes: <...>
- [ ] `go test ./internal/auth -run Integration` exits 0
- [ ] All Actions checkboxes above are `[x]`
```

The scenarios should map 1:1 to the milestone PRD's "Integration contract" section. If the PRD lists 5 scenarios, the integration-verify task has 5 DoD items (one per scenario), at minimum.

## DoD for `chore` tasks

Chores have minimal DoD because they're not user-facing. Acceptable patterns:

```markdown
- [ ] `go build ./...` succeeds
- [ ] `go vet ./...` produces no warnings
- [ ] CHANGELOG.md updated with the change
- [ ] All Actions checkboxes above are `[x]`
```

For a dependency bump:

```markdown
- [ ] `go.mod` lists the new version
- [ ] `go test ./...` still passes
- [ ] No `// TODO: revisit after upgrade` comments left in code
```

## DoD for `bugfix` tasks

Bugfix DoD MUST include a regression test. This is non-negotiable.

```markdown
- [ ] Regression test `TestBugXXX` exists and demonstrates the original bug
  (i.e., it fails without the fix, passes with it)
- [ ] Test `TestBugXXX` passes
- [ ] All previously-passing tests still pass
- [ ] All Actions checkboxes above are `[x]`
```

Without the regression test, the bug will come back — and there won't be a tripwire.

## How to draft DoD when writing a task

When opening a task (see `working-on-task.md`), draft the DoD **before** writing the Actions, not after. The DoD defines "what does done mean"; the Actions define "what do I need to do to get there."

Order:

1. Read the milestone PRD's Integration contract and the epic doc's Acceptance criteria.
2. Decide which of those criteria this specific task contributes to.
3. Write DoD items that, when all `[x]`, mean this task has done its share.
4. *Then* write Actions: the coding steps needed to make those DoD items pass.

If you find yourself writing an Action that doesn't move any DoD item toward `[x]`, ask why it's there. It might be cargo-culting.

## Reviewing DoD before closing

Before marking a task `done`, the closing checklist (`references/closing-task.md`) re-reads the DoD. For each item:

1. Is it `[x]`? If no, the task can't close.
2. Is the `[x]` honest? Re-run the test, re-grep the code, re-check the scenario.
3. If the item turns out to be impossible or wrong, **do not silently delete it**. Add a Discussion entry explaining why, and either:
   - Mark it `[!]` and either fix it or move to a follow-up task and keep this one `in_progress`
   - Acknowledge it was a wrong DoD (rare) and add a Discussion entry explaining the discovery

The discipline of re-checking each DoD item is the difference between "task closed because I marked it" and "task closed because it's actually done."

## The relationship between Actions and DoD

A task is `done` only when:

- Every Action is `[x]`
- Every DoD item is `[x]`

The Actions can be completed without the DoD passing (you can write the code without it being wired correctly). The DoD can theoretically pass without all Actions checked, but in practice if a DoD passes with unchecked Actions, you forgot to update the Action checkboxes — fix them before closing.

The two sections are complementary, not redundant:

- **Actions** = the LLM's to-do list (what to do, in order)
- **DoD** = the success criteria (how we know it's really done)

## DoD smell tests

Red flags that your DoD won't catch incomplete work:

- All items can be checked just by reading the code, never by running it
- No mention of any test name
- No mention of any specific file or function
- Uses adjectives ("good", "clean", "correct", "robust", "complete")
- The same DoD could apply to many different tasks
- A reviewer wouldn't know what to look at to verify

If 2+ red flags apply, rewrite the DoD. It's not doing its job.
