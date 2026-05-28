# Ending a session mid-task

Used when the session is ending but the current task isn't done. Critical for vibe coding because the next session (maybe days later) will have zero memory of the current state.

**Prerequisites:** read `references/structure.md`.

## Why this matters

Mid-task state lives in the LLM's working memory: what was just tried, what the next step was going to be, what subtle issue was just spotted. None of that survives the session unless it's written down. If you leave the task in an ambiguous state, the next session will either re-do work or get stuck guessing what was meant.

## Checklist

```
- [ ] Update every Actions checkbox to its true current state ([ ], [x], or [!])
- [ ] Update every DoD checkbox to its true current state (honestly — see warning below)
- [ ] Commit any uncommitted work on the branch (or note that it's uncommitted in Discussion)
- [ ] Add a Discussion entry: what was done this session, what's next, any pitfalls
- [ ] Leave status as in_progress (do not flip to done unless actually done — see closing-task.md for the rules)
- [ ] Confirm to the user what was saved and what's left
```

## Warning about DoD honesty at session end

It is tempting at the end of a tiring session to mark DoD items `[x]` because "they're basically done." Do not. DoD items must reflect what is *actually verified*, not what is *plausibly true*.

If a DoD item is "test X passes" and you wrote the test but didn't run it: leave it `[ ]`. Add a Discussion entry noting "the test exists but hasn't been re-run since I changed the implementation" — and that's the first thing to do next session.

The cost of an inaccurate DoD at session end compounds: the next session sees `[x]` and trusts it, skips re-verification, and ships broken code.

## The session-end Discussion entry

Format:

```markdown
### YYYY-MM-DD — Session pause
Done this session: brief summary of what's now in the code.
DoD state: which DoD items are verified, which are partially done, which are untouched.
Next step: the very next concrete action when resuming.
Watch out for: any subtle issue, half-finished refactor, or non-obvious context.
```

Example:

```markdown
### 2026-05-22 — Session pause
Done this session: refresh endpoint wired (POST /auth/refresh), happy path tested.
DoD state:
  - TestRefreshHappyPath: [x] passes locally
  - TestRotatedTokenReuseFails: [ ] test exists but is failing — need to investigate
    why the rotation isn't marking the old token invalid
  - "Function X called from Y": [x] verified by grep
  - Migration applied: [x] applied locally, not yet committed
Next step: debug TestRotatedTokenReuseFails — start by adding logging in
RefreshHandler.rotate() to see what state the old token ends in.
Watch out for: the test suite uses a clock fixture; new tests need to inherit
from TestCaseWithFrozenTime or token expiry checks will be flaky.
```

The "Watch out for" line is gold. It's the kind of thing that's obvious to you right now and completely invisible to a future session. Write it down even if it feels small.

The "DoD state" block is the most important part of the entry. It's the precise handoff that lets the next session pick up without re-deriving the verification state.

## What "next step" should look like

Concrete and immediately actionable. Not "continue the implementation" — that's useless. Instead: "debug TestRotatedTokenReuseFails by adding logging in RefreshHandler.rotate() to inspect token state after rotation."

A future session should be able to read the next step and start typing code, not re-derive what to do.

## On uncommitted work

Strong preference: commit before ending the session, even if the commit is `WIP: ...`. A WIP commit on the task branch is easy to amend or squash later.

If for some reason you must leave uncommitted changes, note this explicitly in the Discussion entry:

```markdown
### 2026-05-22 — Session pause (uncommitted)
... [as above] ...
Uncommitted: changes in src/auth/refresh.ts and tests/auth/refresh.test.ts.
Run `git status` on branch task/TASK-042-refresh-rotation to see them.
```

This makes resuming explicit rather than surprising.

## What stays in_progress

The task stays `status: in_progress` when the session ends. The branch is still active. The next session will see `in_progress` in `task.sh status` and know exactly where to resume.

Do NOT set `status: blocked` just because the session is ending. `blocked` is for external dependencies, not for "I have to log off." If the work is genuinely blocked, see `handling-blockers.md`.

Do NOT set `status: done` just because the session is ending and you want closure. `done` requires the full closing-task audit. If you haven't done the audit, the task is not done.

## When the user just stops

If the user ends the conversation without explicit signal ("ok thanks bye", or just goes quiet), still go through this checklist mentally:

- Are Actions checkboxes accurate? If not, update.
- Are DoD checkboxes accurate? If not, update — especially important because they tend to drift toward optimism during work.
- Is there uncommitted work? If yes, mention it.
- Was there a non-trivial decision made this session? If yes and not yet logged, log it.

It's OK to skip the full session-pause Discussion entry if very little happened — but always update checkbox states. The mismatch between checkbox state and reality is the #1 source of confusion in the next session.
