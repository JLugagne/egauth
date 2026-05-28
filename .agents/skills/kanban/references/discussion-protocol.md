# Discussion protocol

The `## Discussion` section is the most valuable part of the kanban. It's what makes context survive across sessions. Without disciplined logging, the system devolves into a glorified to-do list.

**Prerequisites:** read `references/structure.md` for the Discussion format.

## When to write an entry

Trigger heuristic: if a future session would have to *re-make this decision* without knowing it had already been made, log it.

Concrete triggers:

- Choosing between libraries, frameworks, or external services.
- Architectural choices (pattern, data flow, ownership of state).
- API shape: route names, payload structure, error formats.
- Data model: entity boundaries, foreign keys, naming.
- Naming that wasn't obvious and the alternatives matter.
- Tradeoffs explicitly accepted (e.g. "we picked simpler over faster because X").
- Constraints discovered mid-task that affect the design.
- **Changes to the Definition of Done after the task started.** Always log these. A moved DoD item is a moved goalpost; without a Discussion entry, the change is invisible.
- **Discovery that a DoD item is impossible or wrong.** Same logic — moving away from a DoD must leave a trace.
- Anything you almost did differently — the "almost" is worth recording.

Do NOT log:

- Trivia (variable renames, formatting, obvious refactors).
- Implementation details that any competent reader could reconstruct from the code.
- Things already explained in code comments at the call site.

If in doubt, prefer logging. A useless entry costs little; a missing one costs a future session.

## Format

```markdown
### YYYY-MM-DD — Short decision title
Decision: what was decided, in one sentence.
Rationale: why, in 1-3 sentences. Include the criterion that mattered most.
Alternatives considered: what was rejected and why, briefly.
```

The title should be searchable. "Library choice" is weak; "Choice of OAuth library" is strong. "Cache strategy" is weak; "TTL strategy for session cache" is strong.

The `Alternatives considered` block is optional only when there was genuinely no alternative. In practice, almost every decision had alternatives — write them down.

## Append-only

Never edit or delete a past entry. Two reasons:

1. The historical record is the value — what you *thought* at the time, even if you later changed your mind.
2. Editing is a slippery slope toward rewriting history to flatter the present state.

If a decision is reversed, add a new entry today that supersedes it:

```markdown
### 2026-06-15 — Refresh token storage (supersedes 2026-05-20)
Decision: store refresh tokens in httpOnly cookies, not in DB.
Rationale: rotation was less frequent than expected, cookies are simpler to invalidate
on logout, and the earlier reasoning about log leaks was overstated.
Alternatives considered: DB storage (the original choice — see entry from 2026-05-20).
```

The older entry stays untouched. A reader scanning the section sees the full evolution.

## Where to log — task vs epic

- **Task Discussion** — decisions specific to this task. Implementation choices, sub-component design, local tradeoffs.
- **Epic `doc.md` Design decisions** — decisions that apply to all tasks in the epic. Architectural choices, shared conventions, cross-cutting tradeoffs.

When in doubt, log at the task level. It's easier to promote a decision to the epic later (by referencing it) than to dig it out of an epic doc when working on a sub-task.

## Cross-references

When a decision in task A is referenced from task B's Discussion, name the source:

```markdown
### 2026-05-22 — Reusing the OAuth client builder
Decision: use the same OAuth client builder as TASK-042.
Rationale: configuration is identical; duplicating would create drift risk.
See TASK-042's Discussion entry of 2026-05-20 for the original rationale.
```

This lets a reader follow the chain without scanning every task file.

## What "non-trivial" means in practice

Threshold: if you spent more than ~30 seconds thinking about the choice, it's probably worth logging. Decisions that took zero thought (obvious, only-one-way) don't need entries.
