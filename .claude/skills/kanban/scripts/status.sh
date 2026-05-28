#!/usr/bin/env bash
# status.sh — print overview of all milestones with task counts per status
set -euo pipefail

TASKS_DIR="${TASKS_DIR:-.tasks}"

# Extract a YAML field value from the front matter of a markdown file.
# Front matter is delimited by --- lines at the start of the file.
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

# Find all milestone folders (M<N>-*)
milestones=()
while IFS= read -r -d '' dir; do
    milestones+=("$(basename "$dir")")
done < <(find "$TASKS_DIR" -maxdepth 1 -type d -name 'M[0-9]*-*' -print0 | sort -z)

if [ ${#milestones[@]} -eq 0 ]; then
    echo "No milestones found in $TASKS_DIR/"
    echo "Create one with a folder like '$TASKS_DIR/M1-<slug>/'"
    exit 0
fi

for ms in "${milestones[@]}"; do
    declare -A counts=(
        [backlog]=0
        [todo]=0
        [in_progress]=0
        [blocked]=0
        [done]=0
        [cancelled]=0
    )
    total=0

    while IFS= read -r -d '' task; do
        status=$(get_field "$task" "status")
        [ -z "$status" ] && status="todo"
        if [ -n "${counts[$status]+x}" ]; then
            counts[$status]=$((counts[$status] + 1))
        fi
        total=$((total + 1))
    done < <(find "$TASKS_DIR/$ms" -type f -name 'TASK-*.md' -print0)

    printf "%-20s %3d tasks   %d done, %d in_progress, %d todo, %d blocked, %d backlog" \
        "$ms" "$total" \
        "${counts[done]}" "${counts[in_progress]}" "${counts[todo]}" "${counts[blocked]}" "${counts[backlog]}"

    if [ "${counts[cancelled]}" -gt 0 ]; then
        printf ", %d cancelled" "${counts[cancelled]}"
    fi
    echo

    unset counts
done
