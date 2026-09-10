#!/usr/bin/env bash
# Consumer module smoke test for the published root go.mod.
#
# External consumers resolve github.com/JLugagne/egauth through the module proxy and cannot
# see the repository's local `replace` directives. This script builds a throwaway consumer
# module that requires the root module, serves every dependency from the local module cache
# as a file:// proxy, and asserts that both `go list -m all` and `go mod download all`
# succeed. It fails if the root go.mod requires a version no proxy can serve (for example a
# placeholder pseudo-version that only resolves inside the repository's own workspace).
#
# Performs NO network access. Requires Go >= 1.26.7 and a module cache populated with the
# root module's dependencies, including the adapter version pinned in go.mod. Warm the cache
# first if needed with:
#   go mod download github.com/JLugagne/egauth/adapters/pgx@<pinned-version>
#
# Usage: scripts/consumer-smoke.sh [path-to-repo]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CORE='github.com/JLugagne/egauth'
ADAPTER='github.com/JLugagne/egauth/adapters/pgx'
CORE_VERSION='v0.11.0'
PLACEHOLDER='v0.0.0-00010101000000-000000000000'

# Pick a Go binary >= 1.26.7 without triggering a toolchain download.
GO="$(command -v go)"
if ! GOTOOLCHAIN=local "$GO" version 2>/dev/null | grep -qE 'go1\.26\.(7|[89]|[1-9][0-9])'; then
  CACHED="$(find "$(go env GOMODCACHE)/golang.org" -maxdepth 1 -name 'toolchain@v0.0.1-go1.26.7.*' -type d 2>/dev/null | head -1)"
  [ -n "$CACHED" ] || { echo "SKIP: no go1.26.7 toolchain available"; exit 2; }
  GO="$CACHED/bin/go"
fi

MODCACHE_SRC="$(GOTOOLCHAIN=local "$GO" env GOMODCACHE)"
ADAPTER_VERSION="$(cd "$REPO" && GOWORK=off GOTOOLCHAIN=local "$GO" list -m -f '{{.Version}}' "$ADAPTER")"

echo "root module adapter pin: $ADAPTER@$ADAPTER_VERSION"
if [ -z "$ADAPTER_VERSION" ] || [ "$ADAPTER_VERSION" = "$PLACEHOLDER" ]; then
  echo "FAIL: root go.mod requires an unresolvable placeholder version for $ADAPTER" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

# ---- throwaway consumer that imports egauth exactly as a downstream user would ------------
mkdir -p "$WORK/consumer"
cat > "$WORK/consumer/go.mod" <<EOF
module example.com/consumer

go 1.26.7

require $CORE $CORE_VERSION

replace $CORE => $REPO
EOF
cat > "$WORK/consumer/main.go" <<'EOF'
package main

import _ "github.com/JLugagne/egauth/event"

func main() {}
EOF

# ---- file:// proxy overlay: .info for every cached real module, then the raw cache ---------
mkdir -p "$WORK/proxy"
while IFS= read -r f; do
  rel="${f#"$MODCACHE_SRC"/}"; d="$(dirname "$rel")"; b="$(basename "$rel" .mod)"
  mkdir -p "$WORK/proxy/$d"
  printf '{"Version":"%s","Time":"2024-01-01T00:00:00Z"}' "$b" > "$WORK/proxy/$d/$b.info"
done < <(find "$MODCACHE_SRC/cache/download" -name '*.mod' ! -name 'go.mod' 2>/dev/null)

run() {
  mkdir -p "$WORK/gomodcache" "$WORK/gocache"
  ( cd "$WORK/consumer" && rm -f go.sum && \
    env GOWORK=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=mod \
        GOMODCACHE="$WORK/gomodcache" GOCACHE="$WORK/gocache" \
        GOPROXY="file://$WORK/proxy,file://$MODCACHE_SRC/cache/download" "$GO" "$@" 2>&1 )
}

echo
echo "== consumer: go list -m all (offline, file:// proxy) =="
if ! OUT="$(run list -m all)"; then
  printf '%s\n' "$OUT"
  echo "FAIL: go list -m all failed" >&2
  exit 1
fi
if ! printf '%s\n' "$OUT" | grep -qF "$ADAPTER $ADAPTER_VERSION"; then
  printf '%s\n' "$OUT"
  echo "FAIL: $ADAPTER@$ADAPTER_VERSION missing from the module graph" >&2
  exit 1
fi
if printf '%s\n' "$OUT" | grep -qF "$PLACEHOLDER"; then
  echo "FAIL: placeholder pseudo-version present in the module graph" >&2
  exit 1
fi
echo "PASS: module graph resolves"

echo
echo "== consumer: go mod download all (offline, file:// proxy) =="
if ! OUT="$(run mod download all)"; then
  printf '%s\n' "$OUT"
  echo "FAIL: go mod download all failed" >&2
  exit 1
fi
echo "PASS: all modules download"

echo
echo "PASS: consumer smoke test"
