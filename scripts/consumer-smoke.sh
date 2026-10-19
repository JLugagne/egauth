#!/usr/bin/env bash
# Consumer module smoke test for every published module (core, adapters/pgx, adapters/otel).
#
# External consumers resolve each module through the module proxy and cannot see the repository's
# `replace` directives or go.work. This script builds a throwaway consumer module that requires all
# three published modules at CORE_VERSION (the value scripts/sync-versions.sh keeps equal to the
# VERSION file), maps each module path to its checkout directory, serves every third-party
# dependency from the local module cache as a file:// proxy, and asserts that `go list -m all`,
# `go mod download all` and `go build` succeed, and that `go vet` is clean on one package per
# published module (named explicitly: go vet reports nothing for dependencies of the packages it
# is given).
#
# The script first warms the module cache from the configured public proxy with the dependency
# graph of every published module; the offline run is the assertion. Requires Go >= 1.26.7 and
# network access to GOPROXY for the warm-up.
#
# Usage: scripts/consumer-smoke.sh [path-to-repo]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CORE='github.com/JLugagne/egauth'
PGX='github.com/JLugagne/egauth/adapters/pgx'
OTEL='github.com/JLugagne/egauth/adapters/otel'
CORE_VERSION='v0.17.0'
PLACEHOLDER='v0.0.0-00010101000000-000000000000'

# Pick a Go binary >= 1.26.7 without triggering a toolchain download.
GO="$(command -v go)"
if ! GOTOOLCHAIN=local "$GO" version 2>/dev/null | grep -qE 'go1\.(26\.(7|[89]|[1-9][0-9])|2[7-9]|[3-9][0-9])'; then
  CACHED="$(find "$(go env GOMODCACHE)/golang.org" -maxdepth 1 -name 'toolchain@v0.0.1-go1.26.7.*' -type d 2>/dev/null | head -1)"
  [ -n "$CACHED" ] || { echo "SKIP: no go1.26.7 toolchain available"; exit 2; }
  GO="$CACHED/bin/go"
fi

MODCACHE_SRC="$(GOTOOLCHAIN=local "$GO" env GOMODCACHE)"

WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

# ---- warm the module cache for the graphs the offline consumer resolves ---------------------
echo
echo "== warm-up: populate the module cache from the configured proxy =="
for m in . adapters/pgx adapters/otel; do
  name="$(echo "$m" | tr '/.' '__')"
  cp "$REPO/$m/go.mod" "$WORK/$name.mod"
  cp "$REPO/$m/go.sum" "$WORK/$name.sum"
  ( cd "$REPO/$m" && GOWORK=off GOTOOLCHAIN=local "$GO" mod download -modfile="$WORK/$name.mod" all )
done

# ---- throwaway consumer that imports one package per published module -----------------------
mkdir -p "$WORK/consumer"
cat > "$WORK/consumer/go.mod" <<EOF
module example.com/consumer

go 1.26.7

require (
	$CORE $CORE_VERSION
	$PGX $CORE_VERSION
	$OTEL $CORE_VERSION
)

replace (
	$CORE => $REPO
	$PGX => $REPO/adapters/pgx
	$OTEL => $REPO/adapters/otel
)
EOF
cat > "$WORK/consumer/main.go" <<'EOF'
package main

import (
	_ "github.com/JLugagne/egauth/adapters/otel"
	_ "github.com/JLugagne/egauth/adapters/pgx/pgxstore"
	_ "github.com/JLugagne/egauth/event"
)

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
for m in "$CORE" "$PGX" "$OTEL"; do
  printf '%s\n' "$OUT" | grep -qF "$m $CORE_VERSION" || { printf '%s\n' "$OUT"; echo "FAIL: $m@$CORE_VERSION missing from the module graph" >&2; exit 1; }
done
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
echo "== consumer: go build + go vet, one package per published module =="
if ! OUT="$(run build ./... && run vet "$OTEL" "$PGX/pgxstore" "$CORE/event")"; then
  printf '%s\n' "$OUT"
  echo "FAIL: consumer build or vet failed" >&2
  exit 1
fi
echo "PASS: consumer builds and vets"

echo
echo "PASS: consumer smoke test"
