#!/usr/bin/env bash
# dump.sh — emit JSON array of all tasks in a milestone
# Usage: dump.sh <milestone>
set -euo pipefail

TASKS_DIR="${TASKS_DIR:-.tasks}"
MS="${1:-}"

if [ -z "$MS" ]; then
    echo "Error: milestone argument required" >&2
    exit 1
fi

MS_DIR="$TASKS_DIR/$MS"
if [ ! -d "$MS_DIR" ]; then
    echo "Error: milestone folder '$MS_DIR' not found" >&2
    exit 1
fi

# Extract the raw YAML front matter (between the two --- lines)
extract_fm() {
    awk '
        BEGIN { in_fm = 0; count = 0 }
        /^---$/ {
            count++
            if (count == 1) { in_fm = 1; next }
            if (count == 2) { exit }
        }
        in_fm { print }
    ' "$1"
}

# Extract a scalar field from front matter
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

# Extract blocked_by as a JSON array.
# Supports inline form (blocked_by: [TASK-001, TASK-002]) and empty [].
get_blocked_by() {
    local file="$1"
    local raw
    raw=$(get_field "$file" "blocked_by")
    # Strip brackets and split on comma
    raw="${raw#[}"
    raw="${raw%]}"
    if [ -z "$raw" ] || [ "$raw" = " " ]; then
        echo "[]"
        return
    fi
    # Build JSON array via jq
    echo "$raw" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        jq -R . | jq -s .
}

# Count checkboxes in a named section (## Section header → next ## or EOF)
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
            printf "{\"done\":%d,\"open\":%d,\"blocked\":%d}",
                (done+0), (open+0), (blocked+0)
        }
    ' "$file"
}

# Backwards-compat: also count ## Todo (legacy v1 schema). If a file has both
# ## Todo and ## Actions, ## Actions wins (returned as action_stats).
count_actions() {
    local file="$1"
    local actions_count
    actions_count=$(count_section "$file" "Actions")
    # If Actions section is empty (no checkboxes at all), try the legacy Todo section.
    if [ "$actions_count" = '{"done":0,"open":0,"blocked":0}' ]; then
        local has_actions
        has_actions=$(awk '/^## Actions$/ { found=1 } END { print (found ? "yes" : "no") }' "$file")
        if [ "$has_actions" = "no" ]; then
            count_section "$file" "Todo"
            return
        fi
    fi
    echo "$actions_count"
}

# Collect all task files
task_files=()
while IFS= read -r -d '' f; do
    task_files+=("$f")
done < <(find "$MS_DIR" -type f -name 'TASK-*.md' -print0 | sort -z)

# Build JSON via jq for proper escaping
tasks_json="[]"
for f in "${task_files[@]}"; do
    id=$(get_field "$f" "id")
    title=$(get_field "$f" "title")
    description=$(get_field "$f" "description")
    milestone=$(get_field "$f" "milestone")
    epic=$(get_field "$f" "epic")
    status=$(get_field "$f" "status")
    priority=$(get_field "$f" "priority")
    type_field=$(get_field "$f" "type")
    [ -z "$type_field" ] && type_field="feature"
    branch=$(get_field "$f" "branch")
    blocked_by=$(get_blocked_by "$f")
    action_stats=$(count_actions "$f")
    dod_stats=$(count_section "$f" "Definition of Done")

    task_obj=$(jq -n \
        --arg id "$id" \
        --arg title "$title" \
        --arg description "$description" \
        --arg milestone "$milestone" \
        --arg epic "$epic" \
        --arg status "$status" \
        --arg priority "$priority" \
        --arg type "$type_field" \
        --arg branch "$branch" \
        --arg path "$f" \
        --argjson blocked_by "$blocked_by" \
        --argjson action_stats "$action_stats" \
        --argjson dod_stats "$dod_stats" \
        '{id: $id, title: $title, description: $description,
          milestone: $milestone, epic: $epic, status: $status,
          priority: $priority, type: $type, blocked_by: $blocked_by,
          branch: $branch, path: $path,
          action_stats: $action_stats, dod_stats: $dod_stats}')

    tasks_json=$(echo "$tasks_json" | jq --argjson t "$task_obj" '. += [$t]')
done

echo "$tasks_json"
