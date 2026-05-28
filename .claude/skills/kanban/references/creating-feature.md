# Creating a new feature

The most delicate workflow. A new feature means writing a milestone PRD, decomposing into epics with acceptance criteria, then decomposing each epic into tasks with Definition of Done — *all before any code is written*. The user is doing vibe coding and trusts you to structure the work, but the structure must be validated explicitly before files hit disk.

**Prerequisites:** read `references/structure.md` for the file format and folder layout, `references/milestone-planning.md` for the PRD process, and `references/definition-of-done.md` for the DoD format.

## Two-phase validation

Feature creation has **two** validation gates, not one:

1. **PRD validation** — the user approves what the milestone is supposed to deliver, before any decomposition.
2. **Decomposition validation** — the user approves the epic/task structure and the DoD of the first task.

Skipping either gate produces drift: PRD without decomposition validation means the structure may not actually deliver the PRD; decomposition without PRD validation means the structure may be perfectly internally consistent but not what the user wanted.

## Checklist

```
- [ ] Clarify scope if genuinely ambiguous (max 3 questions, only if blocking)
- [ ] Propose a milestone name (kebab-case, M<N>- prefix with N = next free integer)
- [ ] Draft a milestone PRD (Goal, Success criteria, Out of scope, Integration contract, Constraints, Risks)
- [ ] Present the PRD to the user
- [ ] WAIT for explicit PRD validation
- [ ] On PRD validation: propose 2-5 epics that decompose the feature
- [ ] For each epic, list 3-8 candidate tasks with one-line descriptions
- [ ] For each epic, propose at least one integration-verify task at the end
- [ ] Present the full structure as a tree, with traceability to PRD Integration contract scenarios
- [ ] WAIT for explicit structure validation
- [ ] On validation: create folder structure, PRD.md, doc.md per epic, task files (with empty DoD section ready to fill)
- [ ] Set the very first task to status: todo, all others to status: backlog
- [ ] Confirm structure was created; do NOT start coding yet
```

## Sizing heuristics

- **Milestone** = a meaningful project phase (e.g. "auth", "billing core", "admin UI"). Usually 2-5 epics. Has a PRD with 3-7 integration scenarios. If the feature is small enough to fit in a single epic, it doesn't need its own milestone — just add the epic to an existing one (and update that milestone's PRD).
- **Epic** = a coherent deliverable, roughly 1-3 days of work with a small fast model, or 1-2 weeks of human work. Anything bigger should split into multiple epics.
- **Task** = one focused session of work, typically a single module/endpoint/component. If a task would have more than ~8 Actions items, it's too big — split it.
- **Integration-verify task** = at least one per epic, usually the last task in the epic. Its DoD mirrors the PRD's Integration contract scenarios that this epic delivers.

## Naming

- Milestone: `M<N>-<kebab-slug>` where `N` is one greater than the highest existing `M<N>-` folder. Slug describes the phase: `M1-auth`, `M2-billing`, `M3-admin-ui`.
- Epic: kebab-case slug under the milestone folder: `oauth/`, `session/`, `password-reset/`.
- Task ID: read `.tasks/.next-id`, increment, zero-pad to 3 digits: `TASK-042`, `TASK-043`. Update `.tasks/.next-id` after allocating.

## Step 1 — Drafting and validating the PRD

Read `references/milestone-planning.md` for the full PRD template and guidance. In short, draft:

- **Goal** — one sentence
- **Success criteria** — 3-5 externally observable claims
- **Out of scope** — 3+ explicit exclusions
- **Integration contract** — 3-7 Given/When/Then scenarios
- **Constraints** — cross-cutting requirements
- **Risks** — known unknowns

Present this to the user as a Markdown block (the literal PRD content). Ask:

> Here's a draft PRD for M<N>-<slug>. Does this capture what you want?
> Anything to add, remove, or change before I decompose this into epics?

Wait for explicit "yes" / "go ahead" / "looks good." Do not proceed to epics on a "maybe."

If the user pushes back on the PRD (e.g., scope reduction, new constraint), revise and re-present. The PRD is the foundation — getting it right is worth a back-and-forth.

## Step 2 — Decomposing into epics and tasks

Once the PRD is validated, decompose it.

Use a compact tree showing:
- Each epic with its purpose
- Each task in the epic with a one-line description and its `type` if non-default
- For each task, which Success criterion or Integration scenario it contributes to (in brackets after the title)
- The final integration-verify task per epic, explicit

Example:

```
M2-billing/
├── core/
│   ├── TASK-042: Define Subscription and Invoice domain models  [SC-1, SC-2]
│   ├── TASK-043: Wire Stripe webhook receiver with signature validation  [IC-1]
│   ├── TASK-044: Persist subscription state transitions  [IC-1, IC-3]
│   ├── TASK-045: Reconciliation job for stuck subscriptions  [SC-4]
│   └── TASK-046 (integration-verify): Webhook → state transition → reconciliation end-to-end
├── checkout/
│   ├── TASK-047: Build hosted checkout redirect flow  [IC-2]
│   ├── TASK-048: Handle success/cancel callback routes  [IC-2]
│   ├── TASK-049: Send confirmation email on completed checkout  [SC-3]
│   └── TASK-050 (integration-verify): End-to-end checkout journey
└── billing-portal/
    ├── TASK-051: Customer portal session creation  [SC-5]
    ├── TASK-052: Embed portal link in account settings  [SC-5]
    └── TASK-053 (integration-verify): Portal link → portal session → return flow
```

Where SC-N refers to the PRD's Nth Success criterion and IC-N to the Nth Integration contract scenario.

Then ask:

> Does this decomposition look right?
> - Any epics to add, merge, or rename?
> - Any tasks missing or out of scope?
> - Do the integration-verify tasks cover the right scenarios?

Do not list Actions items or DoD items at this stage — they'll be drafted when each task is opened.

## Dependencies

Identify hard dependencies between tasks (where B genuinely cannot start until A is done) and populate `blocked_by` accordingly. Only hard dependencies. "It would be nicer to do X first" is *not* a `blocked_by` — it's just a priority signal.

Common hard dependencies:

- Integration-verify tasks are `blocked_by` every task they verify.
- A task that wires X into Y is `blocked_by` the task that creates X (and the task that creates Y, if separate).

If a dependency crosses epic boundaries within the milestone, that's fine. If it crosses milestone boundaries, flag it to the user — usually it means the milestone decomposition needs adjustment.

## On structure validation

When the user says "yes" / "looks good" / "go ahead":

1. Create the milestone folder.
2. Save the validated PRD to `M<N>-<slug>/PRD.md`.
3. For each epic, create its folder and a `doc.md` (use the template in `structure.md`). Fill in Objective from the user's stated intent, Acceptance criteria mapping to the relevant PRD scenarios, Constraints from anything they mentioned. Leave Design decisions / Open questions empty or with placeholders.
4. For each task, create `TASK-NNN.md` with full front matter (including `type:`) and an empty `## Actions` / empty `## Definition of Done` / empty `## Discussion` body. Title and description as proposed.
5. For integration-verify tasks, populate the `verifies:` field in the front matter with the list of verified task IDs.
6. Set the first task (usually the lowest-numbered in the first epic without blockers) to `status: todo`. All others stay `status: backlog`.
7. Update `.tasks/.next-id` to the highest ID used.
8. Run `task.sh status` to confirm the new milestone shows up correctly.
9. Tell the user: "Structure created. The first task is TASK-NNN. I'll draft its Actions and DoD when you ask me to start work on it." Do not begin coding yet.

## What not to do

- Don't create files before BOTH validations (PRD and structure), even partially.
- Don't fill in Actions items or DoD items for tasks at this stage. They're drafted when the task is opened (see `working-on-task.md` and `definition-of-done.md`).
- Don't propose more than 5 epics or more than ~25 tasks for one feature. If the feature is that big, it's actually multiple features — push back and ask the user to scope it down.
- Don't invent constraints. If something isn't specified, leave it for the Discussion of the relevant task when it comes up.
- Don't skip the integration-verify tasks. Every epic should have at least one. Tasks without integration verification are the #1 source of "feature ships but doesn't work" failures.
