#!/usr/bin/env bash
# task.sh — minimal kanban CLI for vibe coding
# Usage:
#   task.sh status
#   task.sh dump <milestone>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TASKS_DIR="${TASKS_DIR:-.tasks}"

# Check dependencies
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required but not installed." >&2
    echo "Install with: brew install jq  (macOS)  or  apt install jq  (Debian/Ubuntu)" >&2
    exit 1
fi

# Check tasks directory exists
if [ ! -d "$TASKS_DIR" ]; then
    echo "Error: $TASKS_DIR directory not found. Run from repo root." >&2
    exit 1
fi

CMD="${1:-}"

case "$CMD" in
    status)
        exec "$SCRIPT_DIR/status.sh"
        ;;
    dump)
        if [ -z "${2:-}" ]; then
            echo "Error: dump requires a milestone argument" >&2
            echo "Usage: task.sh dump <milestone>" >&2
            echo "Available milestones:" >&2
            ls -1 "$TASKS_DIR" 2>/dev/null | grep -E '^M[0-9]+-' >&2 || echo "  (none)" >&2
            exit 1
        fi
        exec "$SCRIPT_DIR/dump.sh" "$2"
        ;;
    check)
        if [ -z "${2:-}" ]; then
            echo "Error: check requires a task file path" >&2
            echo "Usage: task.sh check <path-to-task.md>" >&2
            exit 1
        fi
        exec "$SCRIPT_DIR/check.sh" "$2"
        ;;
    ""|help|--help|-h)
        cat <<EOF
task.sh — minimal kanban CLI

Usage:
  task.sh status              Overview of all milestones
  task.sh dump <milestone>    JSON dump of all tasks in a milestone
  task.sh check <task-path>   Verify a task is safe to close (all Actions+DoD [x])

See the kanban skill's references/scripts.md for details.
EOF
        ;;
    *)
        echo "Error: unknown command '$CMD'" >&2
        echo "Run 'task.sh help' for usage." >&2
        exit 1
        ;;
esac
