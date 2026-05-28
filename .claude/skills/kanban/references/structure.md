# Structure

The schema everything else builds on. Read this before creating or editing any task file, milestone PRD, or epic doc.

## Folder layout

```
.tasks/
├── M1-<milestone-slug>/
│   ├── PRD.md                  # milestone product brief (required)
│   ├── <epic-slug>/
│   │   ├── doc.md              # epic brief
│   │   ├── TASK-001.md
│   │   └── TASK-002.md
│   └── <epic-slug>/
│       ├── doc.md
│       └── TASK-003.md
├── M2-<milestone-slug>/
│   ├── PRD.md
│   └── ...
└── .next-id                    # plain text file: last assigned task number
```

Rules:

- Root is always `.tasks/` at the repo root.
- Milestones are prefixed `M<N>-` with `N` a 1-indexed integer, so they sort chronologically by filename.
- **Every milestone has a `PRD.md`** at its root. The PRD defines what "this milestone is done" means and is referenced by every task.
- Milestone and epic slugs are kebab-case (`auth`, `billing`, `admin-ui`).
- Task IDs are global (not per-milestone): `TASK-001`, `TASK-002`, etc. Zero-padded to 3 digits.
- Task filename is exactly the ID: `TASK-042.md`.
- Each epic folder contains a `doc.md` (the epic brief) plus its task files.
- `.next-id` holds the highest assigned ID so far, as a plain integer (e.g. `42`). Used by scripts to allocate the next ID.

## Task front matter

Every `TASK-NNN.md` starts with this exact YAML block:

```yaml
---
id: TASK-042
title: Implement refresh token rotation
description: Add silent refresh flow for expired access tokens, with rotation on every refresh.
milestone: M1-auth
epic: oauth
status: todo
priority: normal
type: feature
blocked_by: []
branch: ""
---
```

Field reference:

| Field         | Required | Values / Format                                                          |
| ------------- | -------- | ------------------------------------------------------------------------ |
| `id`          | yes      | `TASK-NNN` (zero-padded 3 digits). Must match filename.                  |
| `title`       | yes      | One-line summary. No markdown.                                           |
| `description` | yes      | 1-3 sentence elaboration. Used in `dump` output for search/selection.    |
| `milestone`   | yes      | Folder name, e.g. `M1-auth`. Must match the file's parent's parent dir.  |
| `epic`        | yes      | Folder name, e.g. `oauth`. Must match the file's parent dir.             |
| `status`      | yes      | One of: `backlog`, `todo`, `in_progress`, `blocked`, `done`, `cancelled` |
| `priority`    | yes      | One of: `low`, `normal`, `high`                                          |
| `type`        | yes      | One of: `feature`, `integration-verify`, `chore`, `bugfix`. Defaults to `feature` if absent. |
| `blocked_by`  | yes      | List of task IDs that must be `done` before this can start. `[]` if none.|
| `branch`      | yes      | Git branch name when in progress. `""` until task is started.            |

Status semantics:

- `backlog` — defined but not ready to work on (future milestone, or unrefined)
- `todo` — ready to start, all blockers resolved
- `in_progress` — actively being worked on (branch should exist)
- `blocked` — was in progress, now waiting on external dep
- `done` — every Action AND every DoD checkbox is `[x]`, code shipped
- `cancelled` — abandoned, kept for history

Type semantics:

- `feature` — implements new behavior or capability. Has both `## Actions` and `## Definition of Done`.
- `integration-verify` — proves an existing set of features works end-to-end. `## Actions` is usually short (write tests, run them); `## Definition of Done` is the centerpiece (scenarios that must pass). The front matter should list the verified tasks via an optional `verifies` field (see below).
- `chore` — non-feature work (refactor, dependency bump, docs). Can have minimal DoD.
- `bugfix` — fixes a discovered defect. DoD MUST include a regression test.

For `integration-verify` tasks, an additional optional field is allowed:

```yaml
type: integration-verify
verifies: [TASK-005, TASK-006, TASK-011]
```

`verifies` lists the task IDs whose integration is being proven by this task.

## Task body

Exactly three sections, in this order:

```markdown
## Actions

- [ ] First concrete coding action
- [ ] Second concrete coding action
- [!] Migrate existing tokens (blocked by TASK-040)
- [x] Sketch the API surface

## Definition of Done

- [ ] Test `TestRefreshTokenRotation` passes
- [ ] `RefreshHandler.Refresh` is called from `AuthMiddleware.HandleExpiry` (verified by `grep -r RefreshHandler.Refresh internal/`)
- [ ] End-to-end: expired access token + valid refresh → new access token returned, old refresh rotated out
- [ ] All Actions checkboxes above are `[x]`

## Discussion

### 2026-05-20 — Choice of OAuth library
Decision: use `oauth4webapi` rather than `openid-client`.
Rationale: smaller bundle, no Node-only deps, works in edge runtimes we'll need later.
Alternatives considered: `openid-client` (more battle-tested but heavier),
hand-rolling (rejected, too much spec to implement).
```

### Actions section

Checkbox states:

- `[ ]` — open, not started
- `[x]` — done
- `[!]` — blocked. Always include the cause in parentheses: `- [!] Foo (waiting on TASK-040)` or `- [!] Bar (upstream API down)`.

Items should be concrete and verifiable as coding steps. Prefer "Add zod validation to signup handler" over "Add input validation".

Aim for 3-8 items per task. If you find yourself writing 12+ items, the task is too big — split it.

### Definition of Done section

**This is the section that turns a task from "code was written" into "the feature works."** Every item must be mechanically verifiable: a test name, a grep pattern, a manual scenario described as input + expected output. "Code looks clean" or "no obvious bugs" are NOT DoD — they're not checkable.

Standard DoD patterns:

- **Test passes**: `` - [ ] Test `TestX` passes ``
- **Wired integration**: `- [ ] Function X is called from Y (verified by grep or test)`
- **End-to-end scenario**: `- [ ] Given <input>, when <action>, then <observable outcome>`
- **Migration applied**: `` - [ ] Migration `003_X` applied, table `T` has column `C` ``
- **Coverage of failure case**: `- [ ] When DB connection drops mid-write, request returns 503 (verified by integration test)`
- **No regression**: `- [ ] All previously-passing tests still pass`

Always include this final DoD item:

```markdown
- [ ] All Actions checkboxes above are `[x]`
```

It exists for one reason: to make explicit that **closing a task with unchecked Actions is forbidden**, even when the DoD itself is satisfied.

Aim for 3-6 DoD items. Fewer than 3 means the task is probably too trivial to need DoD (in which case use `type: chore`). More than 6 means the task does too many things — split it.

Read `references/definition-of-done.md` for the full guide.

### Discussion section

Append-only. Each entry is an `###` sub-header with date and short title, followed by structured prose:

```markdown
### YYYY-MM-DD — Short decision title
Decision: what was decided.
Rationale: why.
Alternatives considered: what was rejected and why.
```

Rules:

- Never edit or delete past entries. If a decision is reversed, add a new entry that supersedes the old one.
- Date format is `YYYY-MM-DD`, always.
- Add an entry whenever a non-trivial design choice is made — library, architecture, data model, API shape, error handling strategy. See `discussion-protocol.md` for the trigger heuristic.
- Don't log trivia (e.g. "renamed variable foo to bar"). Discussion is for choices a future session would have to re-make if forgotten.

## Milestone PRD (PRD.md)

Every milestone folder has a `PRD.md` at its root. It is the contract for what "this milestone is done" means.

```markdown
# Milestone PRD: M1-auth

## Goal
One sentence. What capability this milestone delivers.

## Success criteria
Bulleted, measurable. Each one is something an external observer could verify
after the milestone completes.

- A user can sign in with Google and receive a session cookie.
- Sessions expire after 30 days of inactivity.
- A refresh token can be rotated silently without re-authentication.

## Out of scope
Things explicitly NOT in this milestone. Prevents scope creep.

- Multi-factor authentication (deferred to M3).
- SSO with enterprise SAML providers (no current customer needs it).

## Integration contract
End-to-end scenarios that must pass when the milestone is complete. These are
the acceptance scenarios that integration-verify tasks will test.

1. **First login**: A user with no account clicks "Sign in with Google" →
   redirected → consents → returned to the app authenticated, with a session
   cookie set and a user row created in `users` table.
2. **Returning user**: Same flow on subsequent visits returns the existing user
   without creating a duplicate.
3. **Token refresh**: An expired access token + valid refresh token results in
   a new access token + rotated refresh token, transparently to the caller.

## Constraints
Cross-cutting technical or business constraints that affect every epic in
this milestone.

- All endpoints must respond in < 500ms p95.
- OAuth flows must work in iframes (for embedded contexts).
- No PII in logs.

## Risks
Known unknowns. Things that could derail the milestone if they go badly.

- IdP rate limits unknown for token endpoint — needs measurement in TASK-XXX.
- Cookie SameSite behavior may interact poorly with embedded contexts.
```

The PRD is read at the start of any task within the milestone. Read `references/milestone-planning.md` for the full guide on writing PRDs.

## Epic doc.md

Every epic folder has a `doc.md` describing the epic's intent. Sections:

```markdown
# Epic: <slug>

## Objective
What this epic delivers, in 2-4 sentences. Business or technical outcome.

## Acceptance criteria
Specific, mechanically verifiable conditions that mean this epic is done.
These are inherited by the integration-verify task at the end of the epic
(if there is one).

- All tasks in this epic have `status: done`.
- The integration-verify task for this epic passes.
- <Epic-specific scenario, e.g.: "OAuth callback handles all 4 IdP error codes
  with appropriate user-facing messages.">

## Constraints
Technical or business constraints that apply to all tasks in this epic.
Examples: target browsers, compliance, latency budget, existing API contracts.

## Design decisions
High-level architectural choices that apply across the epic.
Format same as task Discussion entries: dated, with rationale.

## Open questions
Things deferred or unresolved. Update as they're answered.
```

The epic `doc.md` is read at the start of any task within the epic (see `working-on-task.md`). Decisions made here don't need to be repeated in each task's Discussion — the epic doc is authoritative for the epic level.

## Validation invariants

The skill assumes these hold. The LLM should preserve them when editing:

1. Filename equals `id` field (`TASK-042.md` ↔ `id: TASK-042`).
2. `milestone` field equals the grandparent folder name.
3. `epic` field equals the parent folder name.
4. `status: done` ⇒ all Actions items are `[x]` AND all Definition of Done items are `[x]`.
5. Any ID in `blocked_by` refers to a task that exists somewhere in `.tasks/`.
6. Any ID in `verifies` (for `integration-verify` tasks) refers to a task that exists.
7. `branch` is non-empty when `status` is `in_progress`, `blocked`, or `done`.
8. Every milestone folder contains a `PRD.md`.
9. Every epic folder contains a `doc.md`.
10. Tasks of `type: feature` and `type: integration-verify` must have a non-empty `## Definition of Done` section (≥ 1 item).
