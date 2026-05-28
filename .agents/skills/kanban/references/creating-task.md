# Creating a single task in an existing epic

Used when the user wants to add work to an epic that already exists, without going through the full feature decomposition.

**Prerequisites:** read `references/structure.md` and `references/definition-of-done.md`.

## Checklist

```
- [ ] Confirm the target milestone and epic exist (use task.sh status if unsure)
- [ ] If user description is vague, ask one clarifying question
- [ ] Read the milestone's PRD.md (Integration contract, Success criteria)
- [ ] Read the epic's doc.md (Acceptance criteria, constraints, design decisions)
- [ ] Decide the task type (feature, integration-verify, chore, bugfix)
- [ ] Allocate next ID from .tasks/.next-id
- [ ] Create TASK-NNN.md with full front matter, empty Actions, empty Definition of Done, empty Discussion
- [ ] Set status based on context: todo if ready to start now, backlog otherwise
- [ ] Identify any blocked_by relationships with existing tasks
- [ ] Update .tasks/.next-id
- [ ] Confirm to the user: ID, title, type, status, where it lives
```

## When to draft Actions and DoD items

If the user has already described the work concretely ("add a /health endpoint that returns build SHA and DB status"), draft 3-5 Actions and 3-5 DoD items immediately. Show them to the user for amendment.

If the description is high-level ("add health checks"), leave Actions and DoD empty. They'll be drafted when the task is opened for work (see `working-on-task.md`).

## Choosing the task type

- `feature` (default) — implements new behavior or capability. Use this unless one of the others fits better.
- `integration-verify` — the task's sole purpose is to verify that some set of previously-completed tasks works end-to-end. Use when adding a verification gate to a milestone. Populate `verifies:` in the front matter.
- `chore` — refactor, cleanup, dependency bump, documentation. Has DoD but it's lightweight (`go build` passes, etc.).
- `bugfix` — fixes a defect. **MUST have a regression test in DoD.** This is the most important rule for bugfix tasks — without a regression test, the bug will silently come back.

If you're not sure between `feature` and `chore`, lean `feature`. Chore is for truly internal work that doesn't affect behavior.

## Status decision

- `status: todo` — the user is starting this now, or it's the obvious next thing in the epic.
- `status: backlog` — it's added for later, no immediate work planned.
- Never start a new task at `in_progress`. The transition to `in_progress` always happens when the task is opened (see `working-on-task.md`).

## Where to put it

The task lives in the named epic folder. Filename is `TASK-NNN.md` matching the `id` field.

If the user says "add a task" without naming an epic, ask which epic — don't guess. Misplacing a task means moving it later, which is friction.

If the right epic genuinely doesn't exist yet, this isn't "creating a task" — it's a small feature. Switch to `creating-feature.md` (or just create the new epic folder with its `doc.md` and put the task in it, if it's truly a single-task addition).

## When the user reports a bug

A bug report is implicitly a request to create a `type: bugfix` task. Procedure:

1. Confirm the bug is reproducible. If you can reproduce it, write down exactly how in the description.
2. Identify which previously-closed task introduced the bug, if known. Reference it in the new task's description.
3. The new task's DoD MUST include:
   - A regression test that fails on the current code and would pass after the fix.
   - The "previously-passing tests still pass" item.
4. If the bug was introduced by a closed task, add a Discussion entry to *that* task referencing the new bugfix task. This is valuable archaeology — it shows the original task was closed prematurely.

This last step is uncomfortable but important. A closed task with a bug discovered later was, in retrospect, not really done. The Discussion entry documents that.

## Linking integration-verify tasks

When creating an `integration-verify` task:

1. Populate `verifies:` with the list of task IDs to be verified.
2. Set `blocked_by:` to the same list (the integration test can't run until those tasks are done).
3. Draft DoD items that mirror the relevant PRD Integration contract scenarios.
4. The Actions are usually just: "Write integration test file", "Set up test harness", "Run tests".
