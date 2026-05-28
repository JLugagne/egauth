# Selecting the next task

Used when the user asks "what should I work on", "what's next", "where were we", or starts a session without naming a specific task.

**Prerequisites:** none beyond the SKILL.md universal rules.

## Checklist

```
- [ ] Run task.sh status
- [ ] Identify the milestone with active work (in_progress > 0), or the earliest non-done one
- [ ] Run task.sh dump <milestone> on that milestone
- [ ] Apply selection rules (see below) to pick a candidate
- [ ] If multiple candidates are equally valid, propose 2-3 to the user
- [ ] If one candidate is clearly the right choice, name it and confirm before loading
```

## Selection rules

Apply in order, stopping at the first that yields a single candidate:

1. **In-progress wins.** If any task has `status: in_progress`, that's where to resume. Pick the one most recently modified (file mtime) if multiple.
2. **Unblock the blocked.** If any `blocked` task's blockers are now `done` (Actions AND DoD both fully `[x]`), it's ready to resume — propose it.
3. **Highest priority `todo`** with no unsatisfied `blocked_by`. Filter the dump for `status: todo`, check that every ID in `blocked_by` is `done`, then sort by priority (`high` > `normal` > `low`).
4. **Tiebreak by lowest ID** — older work first.
5. **If nothing matches at the milestone level**, look at the next milestone. If everything is `done` or `cancelled`, tell the user — the milestone is complete.

### Special case: integration-verify tasks

When an `integration-verify` task becomes eligible (its `verifies` tasks all `done`), prefer it over starting a new feature task in the same epic. The point of integration-verify is to catch premature `done` markings — running it early surfaces issues before more code piles on top.

If an integration-verify task fails (its DoD doesn't pass), the verified tasks were closed prematurely. Open bugfix tasks against them. Then re-run the integration-verify until it passes.

## How to present the choice

If one task is clearly the right next thing:

> The next task is **TASK-042: Implement refresh token rotation** (M1-auth/oauth, priority: high).
> Ready to load it?

If multiple are equally valid (e.g. two `todo` tasks both `high` priority, no blockers):

> Two candidates in M1-auth/oauth:
> - **TASK-042**: Implement refresh token rotation
> - **TASK-045**: Add session revocation endpoint
>
> Which one?

Don't load the task body until the user confirms — loading prematurely wastes context if they pick the other one.

## Edge cases

- **Everything in progress is stale (mtime > 7 days):** mention it. The user may have abandoned that work and want to start fresh.
- **A task has `[!]` items but `status: in_progress`:** the task is partially blocked but work continues on non-blocked items. Propose it but flag the blockers.
- **A task is `in_progress` with all Actions `[x]` but DoD items still `[ ]`:** this is the common case where coding finished but verification didn't. Propose this task — the next step is to verify the DoD, not write new code.
- **The whole milestone is `backlog`:** the user hasn't promoted anything yet. Ask them which epic they want to start with, or propose promoting the first task of the first epic to `todo`.
- **No milestones exist:** the project hasn't been planned yet. Switch to `creating-feature.md` and ask what the project is about.
