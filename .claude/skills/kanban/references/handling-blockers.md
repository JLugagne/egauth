# Handling blockers

Used when work on a task can't proceed because of an external dependency, missing information, or an upstream issue.

**Prerequisites:** read `references/structure.md` for the `[!]` checkbox convention and the `blocked_by` field.

## Two kinds of blockers

1. **Item-level blocker** — one specific Actions or DoD item is blocked, but other items in the task can still proceed.
2. **Task-level blocker** — the whole task can't move forward.

The handling differs.

## Item-level blocker

Change the checkbox from `[ ]` to `[!]` and append the cause in parentheses. This works for both Actions and DoD items:

```markdown
## Actions
- [!] Migrate existing tokens to new format (waiting on TASK-040 to ship)
- [!] Verify rate limits in prod (waiting on staging access)

## Definition of Done
- [!] Test `TestRateLimitedRefresh` passes (test requires staging access, blocked)
```

Keep working on the other items. The task stays `in_progress`. When the blocker clears, change `[!]` back to `[ ]` (or directly to `[x]` if completing it immediately) and continue.

If the blocker is another task in the kanban, *also* add its ID to the task's `blocked_by` front matter field — this makes the dependency visible in `task.sh dump`.

## Task-level blocker

If no Actions or DoD items can proceed:

```
- [ ] Update status from in_progress to blocked
- [ ] Make sure all blocking items (in Actions and DoD) are marked [!] with the cause
- [ ] If the blocker is another task, add its ID to blocked_by
- [ ] Add a Discussion entry explaining the blocker and the expected resolution
- [ ] Inform the user that the task is blocked and on what
```

Example Discussion entry:

```markdown
### 2026-05-22 — Blocked on TASK-040
Cannot proceed with token migration until TASK-040 (new token format) is done.
Stopping here; will resume when TASK-040 ships.
Open items remaining: 3 (all marked [!] in Actions or DoD).
```

## When the blocker clears

```
- [ ] Verify the blocking condition is actually resolved (don't take "should be" for "is")
- [ ] Change [!] items back to [ ] (or [x] if you complete them immediately)
- [ ] If task was blocked: change status from blocked back to in_progress
- [ ] If the resolved blocker was in blocked_by, remove its ID from the list
- [ ] Add a Discussion entry noting the unblock and any new context discovered
```

## Soft vs hard dependencies

Use `[!]` and `blocked_by` only for *hard* dependencies — where progress is literally impossible. Examples of hard:

- Another task must ship its code/data first.
- A decision the user must make.
- An external service that must come online.

Examples that are NOT blockers (don't use `[!]`):

- "It would be cleaner to do X first" — that's a priority signal, not a blocker.
- "I'd prefer to wait until I understand Y better" — that's a research need; do the research as a Todo item.
- "I might want to refactor later" — that's future work; note it but don't block.

The discipline matters because if everything is "blocked", nothing is — the signal becomes useless.

## Escalating to the user

If a task-level blocker depends on user input (a decision they need to make, a credential they need to provide, a question only they can answer), tell them clearly and concretely. Example:

> TASK-042 is blocked: I need the Stripe webhook secret for staging to wire the signature validation. The relevant Todo item is marked [!]. Let me know when you have it.

Don't wait silently. Don't try to guess around it — that just creates work to redo later.
