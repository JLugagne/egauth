#!/usr/bin/env bash
# check.sh — verify a task can be safely closed (all Actions [x], all DoD [x])
# Usage: check.sh <path-to-task.md>
# Exit 0 = task is closeable; exit 1 = task has unchecked items; exit 2 = error
set -euo pipefail

FILE="${1:-}"

if [ -z "$FILE" ]; then
    echo "Error: task file path required" >&2
    echo "Usage: check.sh <path-to-task.md>" >&2
    exit 2
fi

if [ ! -f "$FILE" ]; then
    echo "Error: file '$FILE' not found" >&2
    exit 2
fi

# Extract a YAML field value from front matter
get_field() {
    local file="$1"
    local field="$2"
    awk -v field="$field" '
        BEGIN { in_fm = 0; count = 0 }
        /^---$/ {
            count++
            if (count == 1) { in_fm = 1; next }
            if (count == 2) { exit }
        }
        in_fm && $0 ~ "^"field":" {
            sub("^"field":[[:space:]]*", "")
            gsub(/^["'\'']/, "")
            gsub(/["'\'']$/, "")
            print
            exit
        }
    ' "$file"
}

# Count checkboxes in a named section
count_section() {
    local file="$1"
    local section="$2"
    awk -v section="$section" '
        $0 == "## " section { in_section=1; next }
        /^## / && in_section { in_section=0 }
        in_section && /^- \[x\]/ { done++ }
        in_section && /^- \[ \]/ { open++ }
        in_section && /^- \[!\]/ { blocked++ }
        END {
            printf "%d %d %d", (done+0), (open+0), (blocked+0)
        }
    ' "$file"
}

ID=$(get_field "$FILE" "id")
TITLE=$(get_field "$FILE" "title")
STATUS=$(get_field "$FILE" "status")
TYPE=$(get_field "$FILE" "type")
[ -z "$TYPE" ] && TYPE="feature"

# Read counts: "done open blocked"
read -r actions_done actions_open actions_blocked <<< "$(count_section "$FILE" "Actions")"
read -r dod_done dod_open dod_blocked <<< "$(count_section "$FILE" "Definition of Done")"

# Backwards compat: if no ## Actions section at all, fall back to ## Todo
has_actions=$(awk '/^## Actions$/ { found=1 } END { print (found ? "yes" : "no") }' "$FILE")
if [ "$has_actions" = "no" ]; then
    read -r actions_done actions_open actions_blocked <<< "$(count_section "$FILE" "Todo")"
fi

actions_total=$((actions_done + actions_open + actions_blocked))
dod_total=$((dod_done + dod_open + dod_blocked))

problems=()

# Rule 1: feature and integration-verify tasks must have DoD items
if [ "$TYPE" = "feature" ] || [ "$TYPE" = "integration-verify" ] || [ "$TYPE" = "bugfix" ]; then
    if [ "$dod_total" -eq 0 ]; then
        problems+=("Missing Definition of Done: $TYPE tasks must have at least 1 DoD item")
    fi
fi

# Rule 2: every Actions item must be [x]
if [ "$actions_open" -gt 0 ]; then
    problems+=("Unchecked Actions: $actions_open items still [ ]")
fi
if [ "$actions_blocked" -gt 0 ]; then
    problems+=("Blocked Actions: $actions_blocked items marked [!]")
fi

# Rule 3: every DoD item must be [x]
if [ "$dod_open" -gt 0 ]; then
    problems+=("Unchecked DoD: $dod_open items still [ ]")
fi
if [ "$dod_blocked" -gt 0 ]; then
    problems+=("Blocked DoD: $dod_blocked items marked [!]")
fi

# Output
echo "Task:   $ID - $TITLE"
echo "Type:   $TYPE"
echo "Status: $STATUS"
echo "Actions: $actions_done/$actions_total done ($actions_open open, $actions_blocked blocked)"
echo "DoD:     $dod_done/$dod_total done ($dod_open open, $dod_blocked blocked)"
echo

if [ ${#problems[@]} -eq 0 ]; then
    echo "OK: task is closeable"
    exit 0
else
    echo "NOT CLOSEABLE:"
    for p in "${problems[@]}"; do
        echo "  - $p"
    done
    exit 1
fi
