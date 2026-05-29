# kanban — a file-based kanban skill for vibe coding

A Claude Code skill that gives the LLM a persistent task system across sessions, with verifiable Definition of Done so "task closed" actually means the feature works. Tasks live as Markdown files with YAML front matter; the board emerges from the filesystem.

## Why

Vibe coding sessions are stateless: the LLM forgets between sessions. The kanban gives it somewhere to write down what it learned, why it chose this approach over that one, and what's still on its plate.

But persistence alone isn't enough. Small autonomous LLMs tend to mark tasks `done` as soon as the code compiles, without verifying integration. The result: a board full of `done` tasks for a feature that doesn't actually work. The v2 schema fixes this with a mandatory **Definition of Done** section: every task lists mechanically verifiable acceptance criteria (test names, grep patterns, end-to-end scenarios), and no task can close until every DoD item is `[x]`. A small `task.sh check` script makes this trivially auditable in CI.

The board is optimized for the LLM, not human dashboards. The user trusts the LLM to keep it accurate; git history is the only ground-truth audit trail.

## Install

### Dependencies

The shell scripts need `jq`:

- macOS: `brew install jq`
- Debian/Ubuntu: `sudo apt install jq`

### As a Claude Code skill (per-project)

Place this folder at `.claude/skills/kanban/` in your repo:

```
your-repo/
├── .claude/
│   └── skills/
│       └── kanban/
│           ├── SKILL.md
│           ├── references/
│           └── scripts/
└── .tasks/        # created by the LLM when you ask for the first feature
```

Restart Claude Code. The skill will load automatically when relevant.

### As a global skill (all your projects)

Place this folder at `~/.claude/skills/kanban/` instead. Then it's available in every project. Be aware the convention assumes `.tasks/` at the repo root.

## How it works

### Folder layout

```
.tasks/
├── M1-auth/                    # milestone
│   ├── PRD.md                  # milestone product brief (required)
│   ├── oauth/                  # epic
│   │   ├── doc.md              # epic brief
│   │   ├── TASK-001.md         # task
│   │   └── TASK-002.md
│   └── session/
│       ├── doc.md
│       └── TASK-003.md
└── M2-billing/
    ├── PRD.md
    └── ...
```

### Milestone PRD

Every milestone has a `PRD.md` that defines what "milestone done" means:

```markdown
# Milestone PRD: M1-auth

## Goal
One sentence: what capability this milestone delivers.

## Success criteria
Bulleted, externally observable.

## Out of scope
Explicit exclusions, to prevent scope creep.

## Integration contract
Given/When/Then scenarios that integration-verify tasks will test.

## Constraints
Cross-cutting technical or business requirements.

## Risks
Known unknowns.
```

### Task file

```yaml
---
id: TASK-042
title: Implement refresh token rotation
description: Add silent refresh flow for expired access tokens.
milestone: M1-auth
epic: oauth
status: in_progress
priority: high
type: feature
blocked_by: []
branch: task/TASK-042-refresh-rotation
---
```

Body has three sections:

- `## Actions` — coding steps with checkboxes (`[ ]` open, `[x]` done, `[!]` blocked)
- `## Definition of Done` — mechanically verifiable acceptance criteria (test names, grep patterns, scenarios). Every item must be `[x]` before the task can close.
- `## Discussion` — append-only log of design decisions, dated

Task types: `feature` (default), `integration-verify`, `chore`, `bugfix`. Integration-verify tasks have a `verifies:` field listing the task IDs they validate end-to-end.

### Scripts

Three commands in `scripts/task.sh`:

```bash
./scripts/task.sh status               # overview of all milestones
./scripts/task.sh dump <milestone>     # JSON of tasks in a milestone
./scripts/task.sh check <task-path>    # verify a task is safe to close
```

`check` exits non-zero if any Actions or DoD item is still `[ ]` or `[!]`. Use it before flipping `status: done`, and as a pre-merge check in CI.

To read a specific task, `cat .tasks/M1-auth/oauth/TASK-042.md` — no dedicated command. To update a field, edit the YAML block directly.

## Usage guide

You don't drive the kanban yourself — you talk to the agent. This section shows what to say to get the right behavior, how to set up a project for autonomous execution, and how to recover when something goes off the rails.

### Quick reference: what to say when

| You want to...                              | Say something like...                                        |
| ------------------------------------------- | ------------------------------------------------------------ |
| Start a new project from scratch            | "Plan a new milestone for <feature> using the kanban skill"  |
| Resume after a break                        | "Where were we?" or "What's next?"                           |
| Work on a specific task                     | "Work on TASK-042" or "Continue TASK-042"                    |
| Run several tasks autonomously              | "Run the next 5 tasks" or "Continue until M2 is done"        |
| Audit what's actually done                  | "Run `task.sh check` on every done task in M1, report fails" |
| Add an unplanned task                       | "Add a task to <epic>: <description>"                        |
| Report a bug                                | "TASK-042 introduced a bug: <repro>. Open a bugfix task."    |
| Refactor the plan mid-flight                | "Re-plan M2 — here's what changed: <details>"                |

The agent picks the right workflow from the skill. You don't have to memorize routing.

### Setting up a new project (the one-shot recipe)

This is the workflow that turned a 21-task project from 60% real value into 90%+ in the v2 tests. Follow it in order.

#### Step 1 — Plan with a strong model

Use the strongest model you have access to (Sonnet, Opus, V4 Pro) for planning. **This is the highest-leverage step**: a bad plan ruins every subsequent execution, no matter how good the model running the code.

Prompt template:

```
I want to plan a new milestone using the kanban skill.

Context: <2-4 sentences about the project, the stack, the constraints>

The milestone should deliver: <one sentence>

Please follow `references/creating-feature.md` strictly:
1. First draft the PRD (Goal, Success criteria, Out of scope, Integration
   contract, Constraints, Risks). Show it to me. Wait for my approval.
2. Then propose the epic/task decomposition with traceability to the PRD.
   Show it to me. Wait for my approval.
3. Only then create the files.

For every feature task, the Definition of Done must include at least:
- a named test that proves the behavior,
- a grep-verifiable integration check (function X called from Y),
- an end-to-end Given/When/Then scenario where relevant.

Every epic must end with a `type: integration-verify` task that runs
the PRD's integration contract scenarios for that epic's slice.

Do not start coding. We're only planning.
```

The "do not start coding" line matters — without it the agent sometimes jumps straight to implementation after the plan is approved.

#### Step 2 — Review the PRD before approving

When the agent shows you the PRD, check three things:

1. **Success criteria are externally observable.** If a criterion can only be verified by reading the code, it belongs in a task DoD, not the PRD.
2. **Out of scope has at least 3 items.** If the agent only listed one or two, push back: "What else are we explicitly NOT building? List 3 more."
3. **Integration contract scenarios are concrete.** "User can log in" is too vague. "Given X cookie state, when /api/me is called, then 200 with user JSON" is right.

If anything is off, ask for revisions before approving. You're cheaper to satisfy now than to debug later.

#### Step 3 — Review the task decomposition

When the agent shows the tree, check:

1. **Every task traces to at least one PRD criterion or integration scenario.** The agent should annotate `[SC-1, IC-2]` next to titles.
2. **Each epic ends with an integration-verify task.** If one is missing, ask for it.
3. **No task is too big.** If a task description sounds like 3-4 things in one, ask the agent to split it.
4. **Dependencies (`blocked_by`) make sense.** Integration-verify tasks should be blocked_by everything they verify.

#### Step 4 — Switch to the cheap model for execution

After files are created, switch to a small fast model (Flash, Haiku) for the actual coding. Prompt:

```
The plan is set. Now run tasks autonomously.

For each task you open:
1. Follow `references/working-on-task.md`.
2. Draft DoD before Actions if either is empty.
3. Show me the proposed Actions + DoD, wait for my "go" before coding.
4. Code, update checkboxes honestly, log non-trivial decisions in Discussion.
5. Before closing, run `task.sh check <path>`. If it fails, do NOT close —
   fix the underlying issue.

Start with the first todo task. After it's done, ask me before continuing
to the next, OR I'll say "run N more tasks" to batch-run.
```

#### Step 5 — Batch execution

Once you trust the agent on a few tasks, batch:

```
Run the next 5 tasks autonomously. Open each, draft Actions+DoD, code,
verify with task.sh check, close. Don't ask for my input between tasks
unless task.sh check fails or you need a real design decision.

At the end, give me a summary: tasks closed, any deferred items, any
DoD changes I should know about.
```

This is the "one-shot supervised" mode. You go do something else; the agent works.

### Optimizing the plan

The plan determines 50%+ of final quality. A few high-impact moves:

#### Force traceability

If the agent's tasks don't visibly trace back to the PRD, the integration is wishful thinking. Ask explicitly:

```
For each task you propose, add `[SC-N]` or `[IC-N]` annotations showing
which Success criterion or Integration contract scenario it contributes to.
Any task that doesn't trace to either gets removed or re-justified.
```

#### Force at least one failure case per feature task

Happy-path-only DoD is the second most common failure mode. Ask:

```
For every feature task with user-facing behavior, the DoD must include
at least one failure or edge case (timeout, invalid input, race condition,
error path), not just the happy path.
```

#### Specific DoD language

The exact wording of DoD checkboxes matters. Bad DoD lets the agent claim victory on incomplete work. Tell the planner explicitly:

```
DoD items must be mechanically verifiable. Acceptable forms:
- "Test `TestX` passes" (name the test)
- "Function X is called from Y (verified by grep)"
- "Given <input>, when <action>, then <observable outcome>"
- "Migration <N>_<name> applied, table `T` has column `C`"

Not acceptable: "code works", "tests added", "integration done",
"no obvious bugs", "documented". These all close on `go build` success
and that's the failure mode we're fixing.
```

This is worth pasting in your planning prompt every time. It's the single biggest defense against premature closure.

#### Refuse oversized tasks

If a task has 12+ Actions items in the plan, it's two tasks pretending to be one. Tell the planner:

```
Hard limit: 8 Actions items per task. If a task would have more, split it.
```

#### Frame integration-verify tasks as audit, not feature

Integration-verify tasks have a tendency to become "and add the missing
integration" tasks where the agent does the wiring inside the verify task.
That defeats the point. Tell the planner:

```
Integration-verify tasks must FAIL when an upstream task is incomplete.
Their job is to surface premature closure, not to do the wiring that
should have happened in the original task. If a verify task fails,
the response is "open a bugfix task against the original," not "fix it here."
```

### Optimizing execution

#### Make DoD failures cheap to recover from

If `task.sh check` reports a problem at close time, the agent's first instinct is sometimes to silently delete the failing DoD item. Pre-empt this:

```
If `task.sh check` reports a DoD item not satisfied, do NOT delete it.
Either:
1. Fix the underlying issue and re-check, OR
2. Add a Discussion entry explaining why the DoD was wrong, replace it
   with a correct one, and re-check.

Silently deleting a DoD is the failure mode v2 of this skill is designed
to catch. Don't do it.
```

#### Force re-running tests at close time

The `[x]` next to "Test X passes" should mean "I just ran it." But the agent may have run it once 20 minutes ago and not since. Force the re-run:

```
At close time (before flipping status: done), for every DoD item of the
form "Test X passes", actually re-run the test now and paste the output.
Do not rely on memory of an earlier run.
```

#### Use a different model for reviewing

After a batch of autonomous tasks, hand the review to a more capable model:

```
I've just had Flash run TASK-040 through TASK-045 autonomously.
You (Sonnet) are now the reviewer. For each task:
1. Read the task file (Actions, DoD, Discussion).
2. Open the code that was added/modified.
3. Run `task.sh check`.
4. Spot-check 2 DoD items: does the code actually satisfy what the DoD claims?
5. Report findings as a table: task ID, DoD honesty score (0-3),
   issues found, recommended action.
```

This catches the subtle "marked `[x]` but doesn't actually verify" failures
that `task.sh check` (which only counts checkboxes) can't see.

### When things go wrong

#### "The plan is bigger than I thought"

If you realize after Step 3 that the milestone is too ambitious, stop. Don't go to Step 4. Say:

```
This is too big. Strip it down to the minimum that demonstrates the
core value. Defer everything else to a follow-up milestone with a
placeholder PRD. Re-propose.
```

A 25-task milestone is almost always two 12-task milestones that should have been separated.

#### "A done task turned out to be broken"

Don't quietly fix it inline. Open a bugfix task:

```
TASK-042 was closed but the feature is broken. Repro: <how>.

Open a `type: bugfix` task in the same epic with:
- Description referencing TASK-042 as the cause
- DoD MUST include a regression test that fails without the fix
- Discussion entry on TASK-042 noting that the bug was found post-close

Then work on the bugfix task.
```

The Discussion entry on the original task is the signal that closure was premature. Over time, looking at how many of your `done` tasks have these entries tells you whether your DoD discipline is improving.

#### "The agent keeps closing tasks with unchecked DoD"

This is the failure mode the skill exists to fix, but sometimes the agent
still finds a way (e.g., editing the DoD to remove the unmet item just
before closing). When this happens:

1. Open the task's Discussion. Did the agent log the DoD change? If no,
   that's the violation.
2. Restore the original DoD items from git (`git log -p .tasks/...`).
3. Tell the agent: "You modified the DoD on TASK-XXX without a Discussion
   entry. That's a violation of the closing-task protocol. Restore the
   original DoD, do not close, and explain in Discussion what's missing."

If the same agent repeats this pattern, switch to a stronger model — the
small one isn't following the protocol reliably.

#### "I'm losing track of the project"

Reset by reading the board:

```
Status overview: run `task.sh status`, then dump the active milestone
and give me a one-paragraph summary of where the project is and what's
blocking. Don't load any task body.
```

Then decide if you want to continue, re-plan, or pause.

### Prompts for specific situations

#### Cold start on an existing project (you forgot context)

```
I'm coming back to this project after a break. Use the kanban skill to:
1. Run `task.sh status`
2. Dump the most active milestone
3. Read the milestone PRD
4. Tell me in 5 lines: what we were building, what's done, what's in_progress,
   what should be next.
Do not start working. I just want to remember where we are.
```

#### Mid-project plan revision

```
I want to revise the M2 plan based on what we learned from M1.

Changes:
- <change 1, e.g., "drop the LLM rerank from retrieval pipeline">
- <change 2, e.g., "split the parser into 4 sub-tasks">

For each affected task:
- If not yet started: update Actions/DoD/description in place,
  add a Discussion entry explaining the revision.
- If in_progress or done: leave alone, but adjust subsequent tasks
  to account for the new direction.

Show me the diff before applying.
```

#### Auditing what's actually done

```
For every task in M1 with status=done, run `task.sh check`. Then:
- Open the code referenced in the DoD (test files, integrated functions).
- Verify the DoD items are actually true (not just checked).
- Report: task ID, check.sh result, honest assessment (real-done / fake-done / partial).

Do not modify any task files. This is read-only audit.
```

This is the audit that catches the failures `task.sh check` can't catch
on its own.

### Anti-patterns to avoid

A few things that look helpful but undermine the system:

- **Skipping the PRD step "because the milestone is obvious."** The PRD's value is the Out-of-scope and Integration contract sections. Without them, scope drifts and integration is wishful thinking.
- **Approving the plan without reading it.** The plan is your strongest leverage point. 5 minutes of review here saves hours of debugging later.
- **Letting the agent run "until done" without intermediate checkpoints.** Batch in groups of 3-5 tasks, then review. Pure unsupervised runs accumulate dead code silently.
- **Editing task DoD yourself to make it easier to close.** If you wouldn't accept the agent doing this, don't do it either. Either fix the underlying issue or downgrade the DoD with a Discussion entry explaining why.
- **Marking tasks done from the chat ("ok, mark TASK-042 done").** Always go through `task.sh check` and the closing-task protocol. Shortcuts here defeat the entire point of the skill.

### Cost notes

Rough orders of magnitude (May 2026):

- **Planning a milestone** with a strong model: ~$0.50 to $2 in API costs for a typical 10-15 task milestone. Worth every cent.
- **Executing a task** with a small/cheap model: $0 to $0.10 per task, depending on size and how much context the agent loads.
- **Reviewing a milestone** with a strong model: $1 to $3 to audit 10-15 done tasks. The most cost-effective quality investment.

Total cost of a 4-6 hour autonomous milestone build: usually under $5, often under $1 if the execution model is free. The dominant cost is your time reviewing the plan and the final audit — not the LLM calls.


## Structure of this skill

```
kanban/
├── SKILL.md                            # entry point: concept + routing table
├── references/
│   ├── structure.md                    # file format, front matter, checkboxes
│   ├── scripts.md                      # CLI usage (status, dump, check)
│   ├── milestone-planning.md           # how to write a PRD
│   ├── definition-of-done.md           # how to write verifiable DoD items
│   ├── creating-feature.md             # full feature decomposition workflow
│   ├── creating-task.md                # adding a task to an existing epic
│   ├── selecting-task.md               # picking the next thing to work on
│   ├── working-on-task.md              # execution workflow
│   ├── discussion-protocol.md          # when and how to log decisions
│   ├── handling-blockers.md            # blocker states and resolution
│   ├── closing-task.md                 # marking a task done (audit + check)
│   └── ending-session.md               # session pause without losing context
└── scripts/
    ├── task.sh                         # dispatcher
    ├── status.sh                       # overview implementation
    ├── dump.sh                         # JSON dump implementation
    └── check.sh                        # closeability check
```

The SKILL.md is short and just routes to the right reference. References are loaded only when relevant — progressive disclosure keeps context lean.

## CI integration

A minimal GitHub Actions check that runs `task.sh check` on every task touched in a PR:

```yaml
name: kanban-check
on: pull_request
jobs:
  check-tasks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: sudo apt-get install -y jq
      - name: Check changed tasks
        run: |
          changed=$(git diff origin/${{ github.base_ref }}...HEAD --name-only \
                    | grep -E '^\.tasks/.*TASK-.*\.md$' || true)
          if [ -z "$changed" ]; then
            echo "No task files changed."
            exit 0
          fi
          fail=0
          for f in $changed; do
            # Only check tasks marked status: done
            status=$(grep '^status:' "$f" | awk '{print $2}')
            if [ "$status" = "done" ]; then
              if ! ./.claude/skills/kanban/scripts/task.sh check "$f"; then
                fail=1
              fi
            fi
          done
          exit $fail
```

This catches the failure mode of a PR landing with a `done` task whose Actions or DoD items aren't all `[x]`.

## Design notes

A few deliberate choices, in case you want to fork or extend:

- **DoD is mandatory for feature/integration-verify/bugfix tasks.** Without it, small models close tasks on `go build` success and you ship broken integrations.
- **`integration-verify` is a first-class task type.** Each epic ends with one. Its sole purpose is to prove the previous tasks work together — and it has the authority to reopen them as bugfix tasks if they don't.
- **No `commits:` field in front matter.** Git history can be rewritten (rebase, squash); a cached commit list goes stale silently. The `branch:` field is enough — `git log <branch>` reconstructs the commit list on demand.
- **No `show` or `sync` commands.** `cat` reads a task; direct file editing updates fields. Less surface area, fewer ways to misuse.
- **Global task IDs, not per-milestone.** A file can be moved between epics or milestones without renumbering.
- **Append-only Discussion.** History is the value. Reversed decisions get new dated entries, not edits.
- **`task.sh check` is purely mechanical.** It doesn't verify whether DoD items are *true* — it verifies they're all `[x]`. The honest re-verification of each DoD item is the LLM's job during the closing-task audit. The script catches the simple failure (forgot to update); the LLM catches the subtle one (marked `[x]` but didn't actually verify).

## Migration from v1

If you're coming from the v1 schema (with `## Todo` instead of `## Actions` + `## Definition of Done`):

- The `dump.sh` script reads `## Todo` as a fallback when `## Actions` is absent, so existing tasks keep showing meaningful action counts.
- New tasks should use the v2 schema. Migrate old ones when convenient.
- `task.sh check` on a v1 task will accept it if `## Todo` is fully `[x]` and no DoD items are required by type — but features-by-default require DoD, so most v1 tasks will fail the check until migrated.

## License

Do whatever you want with this.
