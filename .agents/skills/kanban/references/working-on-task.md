# Working on a task

Used once a task is identified (either by the user or via `selecting-task.md`). Covers loading context, drafting DoD and Actions, transitioning to `in_progress`, executing, and updating the file as work progresses.

**Prerequisites:** read `references/structure.md` for the file format. Also read `references/definition-of-done.md` if you will be drafting or updating DoD items. Optionally read `references/discussion-protocol.md` if you'll be making design decisions.

## Checklist: opening the task

```
- [ ] cat the task file to load full context (front matter + Actions + DoD + Discussion)
- [ ] cat the epic's doc.md to load epic-level constraints and decisions
- [ ] cat the milestone PRD.md to load Integration contract and Success criteria
- [ ] If the task has blocked_by IDs, verify each blocker is actually done (Actions AND DoD both fully [x])
- [ ] If Definition of Done is empty, draft 3-6 mechanically verifiable items (see definition-of-done.md)
- [ ] If Actions is empty, draft 3-8 concrete coding items that lead to satisfying the DoD
- [ ] Confirm scope with user if Actions/DoD were just drafted
- [ ] If status was todo: create git branch task/TASK-NNN-<slug>
- [ ] Update status to in_progress and set branch field
- [ ] Begin coding
```

## Why DoD comes first

When drafting a new task, **draft the Definition of Done before the Actions**. The DoD defines "what does done mean for this task"; the Actions are the route to get there.

If you draft Actions first, you tend to write a description of the code you'll write, not a verification of whether it works. DoD-first thinking asks: "What scenario, test, or grep result will prove this task added real value?"

Then Actions become: "What do I need to code so that the DoD passes?"

## Drafting the DoD

See `references/definition-of-done.md` for the full guide. Quick reminders:

- Every DoD item must be mechanically verifiable.
- Trace each DoD item to either a PRD Success criterion, an Integration contract scenario, or the epic's Acceptance criteria.
- Include the mandatory final item: `- [ ] All Actions checkboxes above are [x]`.
- Aim for 3-6 items.

When proposing newly-drafted Actions and DoD to the user, present them as a compact block:

```markdown
TASK-042 — Implement refresh token rotation

Proposed Actions:
- [ ] Add `RefreshTokens` table migration
- [ ] Implement `RefreshHandler` with rotation logic
- [ ] Wire `RefreshHandler` into `AuthMiddleware`
- [ ] Add test for happy path
- [ ] Add test for rotated-token reuse case

Proposed Definition of Done:
- [ ] Test `TestRefreshHappyPath` passes
- [ ] Test `TestRotatedTokenReuseFails` passes
- [ ] `RefreshHandler.Refresh` is called from `AuthMiddleware.HandleExpiry` (grep)
- [ ] Migration `004_refresh_tokens.sql` applied, table has unique index on token_hash
- [ ] All Actions checkboxes above are [x]

Looks good?
```

Wait for approval (or amendments) before transitioning to `in_progress`.

## Branch naming

Pattern: `task/<ID>-<short-slug>` where the slug is 2-4 kebab-case words from the title.

Examples:
- TASK-042 "Implement refresh token rotation" → `task/TASK-042-refresh-rotation`
- TASK-045 "Add session revocation endpoint" → `task/TASK-045-session-revocation`

Write the exact branch name into the `branch:` field of the front matter at the moment you create the branch. If the branch already exists (resuming work), just confirm it matches the front matter.

## Checklist: while working

```
- [ ] As Actions items are completed, change [ ] to [x] immediately
- [ ] As DoD items become satisfied (test written and passing, integration wired and verified), change [ ] to [x]
- [ ] If an Actions sub-item hits a blocker, change [ ] to [!] and note the cause in parentheses
- [ ] If a non-trivial design choice comes up, add a ## Discussion entry (see discussion-protocol.md)
- [ ] If the scope grew or shrank meaningfully, update Actions AND/OR DoD honestly
- [ ] If a DoD item turns out to be wrong or impossible, add a Discussion entry — do NOT silently delete it
- [ ] Commit early and often with messages prefixed by the task ID: "TASK-042: ..."
```

## Checkbox discipline

The checkboxes are the truth of what's been done. Three failure modes to avoid:

- **Marking Action [x] prematurely** ("the code is there, tests are next"). Don't. Mark [x] only when the item is genuinely done as written.
- **Marking DoD [x] when it's actually not verified**. Don't. The DoD's whole point is honesty — claiming a test passes when it doesn't is the failure mode the DoD exists to prevent.
- **Leaving [ ] after work is done** ("I'll update the file later"). Don't. Update the checkbox immediately after finishing, before moving on.

If an Action turns out to be out of scope, *remove it* or move it to a follow-up task. Don't pretend it's done.

If a DoD item turns out to be wrong, **add a Discussion entry** explaining why and either:
- Replace it with a corrected DoD item, or
- Mark it `[!]` and stay `in_progress` until it's resolved, or
- Move it to a follow-up task and remove it from this one, with a Discussion entry explaining the move.

**Never silently delete a DoD item.** That's the equivalent of moving the goalposts after the kick.

## When scope changes

Sometimes you discover the task needs more work than the Actions list captured, or less. Both are normal.

- **More work**: add Actions as you discover them. Keep them concrete.
- **Less work**: remove Actions that are no longer relevant, with a Discussion entry explaining what changed.
- **A whole new sub-problem emerges**: if it's truly out of scope for this task, create a follow-up task (see `creating-task.md`) rather than expanding the current one.

If the DoD itself changes (because the integration target moved, or the scenario was wrong), add a Discussion entry explaining the change and update the DoD. **Then ask yourself**: should the PRD be updated too? If the change reflects a real shift in what the milestone should deliver, the PRD needs to follow.

## Commit messages

Prefix all commits with the task ID: `TASK-042: add refresh endpoint handler`. This lets `git log` reconstruct what work belongs to which task without any cached metadata. If a commit touches multiple tasks (rare), pick the primary one.

## When to stop and write to Discussion

Don't log every micro-decision. Log when:

- You chose between two or more genuinely different approaches.
- You hit a constraint or surprise that changed the plan.
- You made a tradeoff that someone in a future session would want to know about.
- You changed a DoD item (always log this — it's a moving goalpost).

See `discussion-protocol.md` for the full heuristic and format.

## Special case: working on an integration-verify task

Integration-verify tasks have a different rhythm. The Actions are usually short (set up test harness, write the scenarios, run them); the DoD is the heavy section because each scenario from the milestone PRD is a DoD item.

When opening one:

1. Re-read the milestone PRD's Integration contract.
2. For each scenario in scope of this epic, confirm it's a DoD item.
3. Set up the test harness (testcontainers, fixtures, etc.) as Actions.
4. Implement each scenario as a test function.
5. Run them all. If any fail, the task is not done — but **do not lower the DoD bar**. Either fix the underlying tasks (with follow-up bugfix tasks) or escalate to the user that a PRD scenario is unsatisfiable.

If an integration-verify task uncovers bugs in tasks marked `done`: that's exactly what it's for. Open `type: bugfix` follow-up tasks against the buggy tasks. Do not silently "fix in passing" — the bugfix tasks document that the original tasks were closed too eagerly, which is valuable signal.

## When the task is done

All Actions are `[x]`, all DoD items are `[x]`, code is committed, you believe the work is shipped. Move to `references/closing-task.md` — but **do not close yet**. The closing process re-audits the DoD before flipping status, which is the last safety net.
