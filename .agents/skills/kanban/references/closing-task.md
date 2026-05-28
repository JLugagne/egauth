# Closing a task

Used when work on a task is finished and it should be marked `done`. The closing process is the **last safety net** against marking a task done prematurely — it explicitly re-verifies every Action and every DoD item.

**Prerequisites:** read `references/structure.md` and `references/definition-of-done.md`.

## Hard rule

**A task cannot transition to `status: done` until every Actions checkbox AND every Definition of Done checkbox is `[x]`.** This is non-negotiable. No exceptions for "I'll fix it in the next task" or "the DoD was wrong anyway."

If you find yourself wanting to close with unchecked items, you have three options and only three:

1. **Finish them.** Do the remaining work.
2. **Move them to a follow-up task.** Create a new task explicitly, link via `blocked_by` or in Discussion, remove the item from this task (with a Discussion entry).
3. **Mark this task as `cancelled`.** If the premise was wrong, cancel honestly. Don't fake-close.

## Checklist

```
- [ ] Run `task.sh check <path-to-task.md>` — must exit 0 (no problems reported)
- [ ] Every Actions checkbox is [x] (no [ ] or [!])
- [ ] Every Definition of Done checkbox is [x] (no [ ] or [!])
- [ ] All code is committed on the task branch
- [ ] Re-verify each DoD item HONESTLY: re-run the test, re-grep the code, re-check the scenario
- [ ] Add a final Discussion entry summarizing what shipped
- [ ] Update status from in_progress to done
- [ ] Tell the user the task is closed, with the branch name and a one-line summary
```

`task.sh check` is the mechanical safety net: it counts checkboxes and refuses to pass if anything is still `[ ]` or `[!]`. **Run it first.** If it exits non-zero, you don't need to do the rest of the audit — the task isn't closeable yet.

## Pre-close audit (the critical part)

Before flipping `status: done`, go through the audit. Do not skip it even if you're confident.

### Step 1: Audit the Actions section

For each Actions item:

- Is it `[x]`? If `[ ]` or `[!]`, **the task cannot close**.
- Is the `[x]` honest? Did you actually do this, or did you mark it as you went and now you're not sure?
- If you have any doubt, re-check by running the code or reading the file.

If you find any item that was incorrectly marked, change it back. Then either finish it, drop it (Discussion entry + remove), or move it to follow-up.

### Step 2: Audit the Definition of Done — the most important step

For each DoD item:

- Is it `[x]`? If `[ ]` or `[!]`, **the task cannot close**.
- **Re-verify the item right now.** Don't trust the checkbox state from earlier. Specifically:
  - **"Test X passes"** → re-run the test. Show the user the result if non-obvious. Do not trust memory.
  - **"Function X is called from Y"** → re-grep. If grep returns zero matches, the DoD is false.
  - **"End-to-end scenario"** → trace through the code or re-run the scenario manually. Don't assume.
  - **"Migration applied"** → check the DB or migration history. Don't assume.
  - **"No regression"** → re-run the full test suite.

If any DoD item turns out to actually not pass: change it back to `[ ]` and **do not close the task**. Either fix the underlying issue, or open a follow-up task and remove this DoD item with a Discussion entry explaining the discovery.

### Step 3: Audit the integration

This is the audit that catches the most subtle failures. Ask:

- **Is the code I wrote actually wired into the application?** Search for callers. If new functions exist but nothing calls them, the task is not done — the code is dead.
- **Does the task's claimed contribution to the PRD actually exist?** Re-read the relevant Success criterion or Integration contract scenario. Can you trace it through real code paths from input to output?
- **If I removed the test I just added, would the feature still appear to work?** If yes, the test isn't actually testing the feature — it's testing something tangential. The DoD claim "test passes" might be technically true but functionally meaningless.

### Step 4: Audit the title and description

- Does the title still accurately describe what was shipped? If the work drifted, either rewrite the title (with a Discussion entry explaining the drift), or acknowledge that the original task isn't what got built and open a more honest replacement.
- Does the description still match? Same question.

### Step 5: Audit the Discussion

- Glance through the Discussion entries. Would a future session understand the decisions?
- If a non-trivial choice was made during this task but never logged, log it now (with today's date) — better late than never.
- If a DoD item was changed during the task, is the change documented in Discussion?

## The closing Discussion entry

After the audit passes, add a final entry that wraps up the task. Format:

```markdown
### YYYY-MM-DD — Task closed
Shipped: brief summary of what now exists in the codebase as a result.
DoD verified: confirm that each DoD item was re-checked just now (and how).
Branch: task/TASK-NNN-<slug>
Follow-ups: any tasks created as a result of this work (with IDs), or "none".
```

Example:

```markdown
### 2026-05-25 — Task closed
Shipped: silent OAuth refresh with token rotation on every call. Refresh
tokens stored encrypted in the sessions table with a 30-day TTL.
DoD verified:
  - TestRefreshHappyPath: re-run, passes
  - TestRotatedTokenReuseFails: re-run, passes
  - grep "RefreshHandler.Refresh" in internal/ → 2 matches in auth/middleware.go
  - migration 004_refresh_tokens applied (verified via \d refresh_tokens)
  - All previously-passing tests still pass (go test ./... exit 0)
Branch: task/TASK-042-refresh-rotation
Follow-ups: TASK-051 (token cleanup cron), TASK-052 (admin UI to revoke sessions).
```

The "DoD verified" lines are the critical addition — they prove the audit happened, not just claimed.

This closing entry is what a future session reads first when looking back at the task. Make it useful.

## Merging the branch

The skill itself does not dictate merge workflow — that's the user's choice (PR, direct merge, squash-merge, etc.). But:

- Don't delete the branch on its own. Leave that to the user / their normal git workflow. The `branch:` field still references it, and even after deletion, `git log` from a parent branch can find the commits if needed.
- Keep the `branch:` field populated in the closed task — it's the record of where the work happened, useful for archaeology later.

## When to NOT close

- If anything is genuinely deferred to "later", make a follow-up task. The current task is `done` only for what was actually finished. Don't leave a `done` task with a hopeful `[ ]` still hanging — anywhere.
- If the work revealed that the task's premise was wrong (e.g. the feature doesn't make sense the way it was scoped), use `status: cancelled` instead of `done`, with a Discussion entry explaining why.
- If a DoD item turns out to be impossible to satisfy with the current architecture, that's a strong signal. Either the architecture needs to change (which is a bigger conversation with the user) or the DoD was overspecified (also a conversation). Do not close with the DoD item silently dropped.

## After closing an integration-verify task

Integration-verify tasks closing successfully is the strongest signal a milestone is on track. After closing one:

- Check whether all tasks in the verified epic are now `done` (not just the integration-verify task itself).
- If yes, the epic is effectively complete. Mention this to the user.
- Update the epic's `doc.md` Open questions section if anything got resolved by the integration testing.

If an integration-verify task **doesn't** close (DoD items fail), do not close it. The failure means the verified tasks are not actually done. Open bugfix tasks against them. This is exactly the behavior the integration-verify pattern is meant to produce — it surfaces premature `done` markings on prior work.

## After closing

After closing, the natural follow-up is usually one of:

- The next task in the same epic (run `task.sh dump <milestone>`, find next `todo`).
- A follow-up task you just created.
- The integration-verify task for this epic (if you just closed the last feature task).
- Stopping for the session.

Mention the natural next step to the user briefly, but don't auto-load it — let them decide.

## A note on the temptation to close

When working autonomously (especially with a small model), there is a strong pull toward closing tasks because closing feels like progress. Resist this pull. **Slow closing is correct closing.** The audit is not bureaucratic overhead; it is the mechanism that makes the kanban produce trustworthy "done" states. Without honest closing, the board lies, and a lying board is worse than no board at all.

If the audit reveals an issue, you have not "failed to close" — you have **succeeded at catching premature closure**. That is the system working as designed.
