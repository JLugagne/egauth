#!/usr/bin/env bash
# G17: keeps every published-module version pin in lockstep with the VERSION file.
#
# --check  verify only; exit 1 and list every drift found.
# (none)   rewrite the sibling `require` lines and CORE_VERSION to match VERSION, then verify.
#
# Verified: no go.mod requires a sibling published module other than adapters requiring the core;
# adapters/*/go.mod require the core module at v$(VERSION); CORE_VERSION in
# scripts/consumer-smoke.sh equals it; no go.mod comment mentions `replace` while that go.mod has
# no replace directive; RELEASING.md names every published module and says tools is unpublished;
# every tool pin (name@vX) in .github/workflows and RELEASING.md equals its *_VERSION in the Makefile;
# scripts/consumer-smoke.sh builds every published module.
# The unpublished tools module is excluded from the pins.
#
# Usage: scripts/sync-versions.sh [--check] [repo-root]

set -euo pipefail

MODE=rewrite
if [ "${1:-}" = "--check" ]; then MODE=check; shift; fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CORE='github.com/JLugagne/egauth'
SMOKE="$REPO/scripts/consumer-smoke.sh"
RELEASING="$REPO/RELEASING.md"

[ -f "$REPO/VERSION" ] || { echo "FAIL: $REPO/VERSION missing" >&2; exit 2; }
WANT="v$(tr -d '[:space:]' < "$REPO/VERSION")"

SIBLINGS=()
for f in "$REPO"/adapters/*/go.mod; do
  [ -f "$f" ] && SIBLINGS+=("$f")
done

CORE_RE="${CORE//./\\.}"
SMOKE_PFX='[[:space:]]*((export|readonly|declare|typeset|local)([[:space:]]+-[[:alnum:]]+)*[[:space:]]+)?'
MODFILES=("$REPO/go.mod" "${SIBLINGS[@]}")

gomod_code() { sed -E 's#[[:space:]]*//.*$##' "$1"; }

has_replace_directive() {
  gomod_code "$1" | awk '
    /^[[:space:]]*replace[[:space:]]*\(/ { inblock = 1; next }
    inblock && /^[[:space:]]*\)/ { inblock = 0; next }
    inblock && /=>/ { found = 1 }
    /^[[:space:]]*replace[[:space:]]+[^(].*=>/ { found = 1 }
    END { exit found ? 0 : 1 }'
}

rewrite_file() {
  local f="$1" tmp
  shift
  tmp="$(mktemp)"
  sed -E "$@" "$f" > "$tmp"
  cat "$tmp" > "$f"
  rm -f "$tmp"
}

if [ "$MODE" = rewrite ]; then
  for f in "${SIBLINGS[@]}"; do
    rewrite_file "$f" "/=>/! s#^([[:space:]]*(require[[:space:]]+)?${CORE_RE}[[:space:]]+)v[^[:space:]]+#\\1${WANT}#"
  done
  rewrite_file "$SMOKE" "s#^(${SMOKE_PFX}CORE_VERSION=)['\"]?[^'\"[:space:]]*['\"]?#\\1'${WANT}'#"
fi

FAILS=0
fail() { echo "DRIFT: $*" >&2; FAILS=$((FAILS + 1)); }

for f in "${SIBLINGS[@]}"; do
  rel="${f#"$REPO"/}"
  got="$(gomod_code "$f" | { grep -v '=>' || true; } | sed -nE "s#^[[:space:]]*(require[[:space:]]+)?${CORE_RE}[[:space:]]+(v[^[:space:]]+).*#\\2#p" | head -1)"
  [ "$got" = "$WANT" ] || fail "$rel requires $CORE ${got:-<none>}, VERSION says $WANT"
done

smoke_assigns="$(sed -nE "s#^${SMOKE_PFX}CORE_VERSION=['\"]?([^'\"[:space:]]*).*#\\4#p" "$SMOKE")"
if [ -z "$smoke_assigns" ]; then
  fail "scripts/consumer-smoke.sh CORE_VERSION is <unset>, VERSION says $WANT"
else
  while IFS= read -r smoke_got; do
    [ "$smoke_got" = "$WANT" ] || fail "scripts/consumer-smoke.sh CORE_VERSION is $smoke_got, VERSION says $WANT"
  done <<< "$smoke_assigns"
fi

for f in "${SIBLINGS[@]}"; do
  rel="${f#"$REPO"/}"
  while IFS= read -r target; do
    case "$target" in
      .*|/*) ;;
      *) fail "$rel replaces $CORE with $target; an adapter must build against the local core checkout (a relative path) or a plain require" ;;
    esac
  done < <(gomod_code "$f" | sed -nE "s#^[[:space:]]*(replace[[:space:]]+)?${CORE_RE}([[:space:]]+v[^[:space:]]+)?[[:space:]]*=>[[:space:]]*([^[:space:]]+).*#\\3#p")
done

PUBLISHED=("$CORE")
for f in "${SIBLINGS[@]}"; do
  PUBLISHED+=("$(sed -nE 's#^module[[:space:]]+([^[:space:]]+).*#\1#p' "$f" | head -1)")
done

for f in "${MODFILES[@]}"; do
  rel="${f#"$REPO"/}"
  own="$(sed -nE 's#^module[[:space:]]+([^[:space:]]+).*#\1#p' "$f" | head -1)"
  for m in "${PUBLISHED[@]}"; do
    [ "$m" = "$own" ] && continue
    [ "$m" = "$CORE" ] && [ "$f" != "$REPO/go.mod" ] && continue
    m_re="${m//./\\.}"
    if gomod_code "$f" | { grep -v '=>' || true; } | grep -qE "^[[:space:]]*(require[[:space:]]+)?${m_re}[[:space:]]+v"; then
      fail "$rel requires sibling module $m (the core module must not depend on an adapter, and adapters must not depend on each other)"
    fi
  done
done

for f in "${MODFILES[@]}"; do
  rel="${f#"$REPO"/}"
  if grep -qiE '//.*(^|[^[:alnum:]_])replace([^[:alnum:]_]|$)' "$f" \
    && ! has_replace_directive "$f"; then
    fail "$rel has a comment mentioning replace but no replace directive"
  fi
done

[ -f "$RELEASING" ] || fail "RELEASING.md missing"
if [ -f "$RELEASING" ]; then
  grep -qE "${CORE_RE}([^[:alnum:]_/]|\$)" "$RELEASING" || fail "RELEASING.md does not name the core module $CORE"
  for m in "${PUBLISHED[@]:1}"; do
    grep -qF "$m" "$RELEASING" || fail "RELEASING.md does not name published module $m"
  done
  grep -qiE 'tools.{0,80}unpublished|unpublished.{0,80}tools' "$RELEASING" \
    || fail "RELEASING.md does not state that the tools module is unpublished"
fi

MAKEFILE="$REPO/Makefile"
if [ -f "$MAKEFILE" ]; then
  while IFS=: read -r tool var; do
    want="$(sed -nE "s#^${var}[[:space:]]*:=[[:space:]]*(v[^[:space:]]+).*#\\1#p" "$MAKEFILE" | head -1)"
    [ -n "$want" ] || { fail "Makefile has no $var pin"; continue; }
    for doc in "$REPO"/.github/workflows/*.yml "$RELEASING" "$REPO/CONTRIBUTING.md"; do
      [ -f "$doc" ] || continue
      while IFS= read -r got; do
        [ "$got" = "$want" ] || fail "${doc#"$REPO"/} pins $tool at $got, Makefile $var says $want"
      done < <(grep -oE "${tool}@v[0-9][^[:space:]\`'\")]*" "$doc" | sed "s#^${tool}@##")
    done
  done <<'PINS'
golangci-lint:GOLANGCI_LINT_VERSION
govulncheck:GOVULNCHECK_VERSION
syft:SYFT_VERSION
gitsign:GITSIGN_VERSION
cosign:COSIGN_VERSION
PINS
else
  fail "Makefile missing"
fi

for f in "${SIBLINGS[@]}"; do
  mod="$(sed -nE 's#^module[[:space:]]+([^[:space:]]+).*#\1#p' "$f" | head -1)"
  grep -qF "$mod" "$SMOKE" || fail "scripts/consumer-smoke.sh does not build published module $mod"
done

if [ "$FAILS" -ne 0 ]; then
  echo "FAIL: $FAILS version drift(s); run scripts/sync-versions.sh to fix pins" >&2
  exit 1
fi
echo "PASS: all published modules in sync at $WANT"
