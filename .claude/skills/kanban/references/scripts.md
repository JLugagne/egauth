# Scripts

Two commands, both positional arguments, no flags. Designed so the LLM can't easily mis-invoke them.

## `task.sh status`

Overview of the whole board.

**Usage:**
```bash
./scripts/task.sh status
```

**Output (text, default):**

```
M1-auth         12 tasks   8 done, 2 in_progress, 1 todo, 1 blocked, 0 backlog
M2-billing       8 tasks   2 done, 0 in_progress, 5 todo, 1 blocked, 0 backlog
M3-admin-ui     15 tasks   0 done, 0 in_progress, 0 todo, 0 blocked, 15 backlog
```

Sorted by milestone folder name (so chronological if you've used `M1-`, `M2-` prefix).

**When to use:**
- Always at the start of a session.
- Whenever the user asks "where are we", "what's the state", "show me the board".

**What to do with it:**
- If a milestone has `in_progress > 0`, that's almost certainly where to continue.
- If a milestone has only `done`, skip ahead to the next.
- If everything is `backlog`, the project hasn't really started — ask the user what to focus on.

## `task.sh dump <milestone>`

Dump all tasks of a milestone as JSON.

**Usage:**
```bash
./scripts/task.sh dump M1-auth
```

The milestone argument must match a folder name exactly (including the `M<N>-` prefix).

**Output:**

```json
[
  {
    "id": "TASK-001",
    "path": ".tasks/M1-auth/oauth/TASK-001.md",
    "title": "Set up OAuth client",
    "description": "Configure the OAuth client with our IdP, including redirect URIs and scopes.",
    "milestone": "M1-auth",
    "epic": "oauth",
    "status": "done",
    "priority": "high",
    "type": "feature",
    "blocked_by": [],
    "branch": "task/TASK-001-oauth-client",
    "action_stats": {"done": 5, "open": 0, "blocked": 0},
    "dod_stats": {"done": 4, "open": 0, "blocked": 0}
  },
  {
    "id": "TASK-002",
    "path": ".tasks/M1-auth/oauth/TASK-002.md",
    "title": "Implement refresh token rotation",
    "description": "Add silent refresh flow with rotation on every refresh.",
    "milestone": "M1-auth",
    "epic": "oauth",
    "status": "in_progress",
    "priority": "high",
    "type": "feature",
    "blocked_by": [],
    "branch": "task/TASK-002-refresh",
    "action_stats": {"done": 2, "open": 3, "blocked": 1},
    "dod_stats": {"done": 1, "open": 4, "blocked": 0}
  }
]
```

`action_stats` and `dod_stats` are computed on the fly by counting `[x]`, `[ ]`, and `[!]` checkboxes within the `## Actions` and `## Definition of Done` sections respectively. **Both must be fully `done` (all `[x]`, no `open` or `blocked`) before the task can be marked `status: done`.**

**When to use:**
- After `status`, to pick the next task (filter by `status: in_progress` or `todo`, sort by `priority`).
- For semantic search across tasks (load all titles + descriptions, reason about which match a user query).
- For planning (see what's in `backlog` to decide what to promote next).

**What to do with it:**
- Filter by `status`, `epic`, or `priority` in your head — no need for CLI flags.
- To load a specific task's full body, use the `path` field with `cat` or the file-reading tool.
- Don't pipe to `jq` unless absolutely necessary; the JSON is small enough to reason about directly.

## Reading a task body

There is no `task.sh show` command on purpose. To read a task's full Markdown (front matter + Actions + DoD + Discussion):

```bash
cat .tasks/M1-auth/oauth/TASK-002.md
```

Or use the file-reading tool with the `path` from `dump` output.

## `task.sh check <task-path>`

Verify a task is safe to close. This is the mechanical safety net before flipping `status: done`.

**Usage:**
```bash
./scripts/task.sh check .tasks/M1-auth/oauth/TASK-002.md
```

**Output (passing):**
```
Task:   TASK-002 - Implement refresh token rotation
Type:   feature
Status: in_progress
Actions: 5/5 done (0 open, 0 blocked)
DoD:     4/4 done (0 open, 0 blocked)

OK: task is closeable
```

Exit code 0.

**Output (failing):**
```
Task:   TASK-002 - Implement refresh token rotation
Type:   feature
Status: in_progress
Actions: 3/5 done (1 open, 1 blocked)
DoD:     2/4 done (2 open, 0 blocked)

NOT CLOSEABLE:
  - Unchecked Actions: 1 items still [ ]
  - Blocked Actions: 1 items marked [!]
  - Unchecked DoD: 2 items still [ ]
```

Exit code 1.

**When to use:**
- Always before flipping a task to `status: done` (see `closing-task.md`).
- In CI as a pre-merge check on PRs that touch `.tasks/`.
- Anytime you want to sanity-check a task you think is done.

**Rules enforced:**
- Every Actions item must be `[x]` (no `[ ]`, no `[!]`).
- Every DoD item must be `[x]` (no `[ ]`, no `[!]`).
- `feature`, `integration-verify`, and `bugfix` tasks must have at least 1 DoD item.

If `check` returns non-zero, you cannot close the task. Fix the underlying issues first.

## Writing the next task ID

When creating a new task, allocate the next ID by:

1. `cat .tasks/.next-id` (returns e.g. `42`)
2. The new task's ID is `TASK-043` (zero-padded to 3 digits)
3. After creating the file, write the new number back: `echo 43 > .tasks/.next-id`

The scripts don't do allocation — the LLM does, because it's the one creating the file anyway.

## Updating front matter

To update a field (e.g. moving a task to `in_progress` and setting its branch), edit the YAML block directly with the file-editing tool. The format is fixed (see `structure.md`), so a string replacement on `status: todo` → `status: in_progress` is reliable.

There is no `task.sh set-status` or similar — direct file editing is simpler and avoids a fragile CLI.

## Gotchas

- `task.sh dump` will error if the milestone folder doesn't exist. Check `status` output first if unsure.
- `action_stats` only counts checkboxes inside the `## Actions` section; `dod_stats` only counts checkboxes inside `## Definition of Done`. Checkboxes anywhere else in the file are ignored — including in `## Discussion`, which is intended behavior.
- The scripts assume `.tasks/` exists at the current working directory. Run them from the repo root.
- The scripts use `jq` for JSON output. If `jq` isn't installed, they'll error with an install hint.
- Tasks created before the v2 schema (with `## Todo` instead of `## Actions` + `## Definition of Done`) will show `action_stats` based on their `## Todo` section if present, and `dod_stats` of zero. Migrate them when convenient.
