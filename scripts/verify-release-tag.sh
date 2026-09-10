#!/usr/bin/env bash
# Release gate for signed tags.
#
# Fails unless the given tag exists in the repository and carries a signature that
# `git verify-tag` accepts. The gate is read-only: it never creates, moves or pushes refs
# and never touches the work tree, so it is safe to run against a checkout.
#
# The correct verifier must be configured for the signature type (gitsign for keyless
# Sigstore x509, gpg for OpenPGP, ssh-keygen plus gpg.ssh.allowedSignersFile for SSH); see
# RELEASING.md. OpenPGP and SSH verification work fully offline, keyless Sigstore
# verification uses the local Sigstore trust root (the first run may refresh it).
#
# Exit codes: 0 = tag exists and is verifiably signed; 1 = missing, lightweight or
# unverifiable tag; 2 = usage or environment error.
#
# Usage:
#   scripts/verify-release-tag.sh <tag> [repo-path]
#   scripts/verify-release-tag.sh --self-test
#
# --self-test exercises the gate against a throwaway repository in the system temp
# directory (an unsigned tag must be rejected, a missing tag must be rejected, and, when
# ssh-keygen is available, an ephemeral SSH-signed tag must be accepted). It leaves the
# current repository untouched.

set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

usage() {
  cat <<'EOF'
Usage:
  scripts/verify-release-tag.sh <tag> [repo-path]
  scripts/verify-release-tag.sh --self-test

Fail unless <tag> exists in [repo-path] (default: current directory) and
`git verify-tag <tag>` succeeds.

Exit codes: 0 pass, 1 missing/lightweight/unverifiable tag, 2 usage error.
EOF
}

verify_tag() {
  local repo="$1" tag="$2" kind out

  if ! git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: '$repo' is not a git work tree" >&2
    return 2
  fi

  if ! git -C "$repo" show-ref --tags --verify --quiet "refs/tags/$tag"; then
    echo "FAIL: tag '$tag' does not exist in $repo" >&2
    return 1
  fi

  kind="$(git -C "$repo" cat-file -t "refs/tags/$tag")"
  if [ "$kind" != "tag" ]; then
    echo "FAIL: '$tag' is a lightweight tag; release tags must be annotated and signed" >&2
    return 1
  fi

  if out="$(git -C "$repo" verify-tag "$tag" 2>&1)"; then
    printf '%s\n' "$out"
    echo "PASS: tag '$tag' exists and has a verifiable signature"
    return 0
  fi

  printf '%s\n' "$out" >&2
  echo "FAIL: tag '$tag' has no verifiable signature (git verify-tag failed)" >&2
  echo "      configure the verifier for the signature type (gitsign/gpg/ssh) — see RELEASING.md" >&2
  return 1
}

self_test() {
  command -v git >/dev/null 2>&1 || { echo "ERROR: git is required" >&2; return 2; }

  local tmp repo rc=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/verify-release-tag.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  repo="$tmp/repo"
  git init -q -b main "$repo"
  git -C "$repo" config user.name "Release Gate Self-Test"
  git -C "$repo" config user.email "release-gate-selftest@example.invalid"
  git -C "$repo" commit -q --allow-empty -m "self-test"
  git -C "$repo" tag -a v0.0.1 -m "unsigned self-test tag"

  echo "== self-test: unsigned annotated tag must be rejected =="
  if "$SELF" v0.0.1 "$repo"; then
    echo "FAIL: unsigned tag passed the gate" >&2
    rc=1
  else
    echo "PASS: unsigned tag rejected"
  fi

  echo
  echo "== self-test: missing tag must be rejected =="
  if "$SELF" v9.9.9 "$repo"; then
    echo "FAIL: missing tag passed the gate" >&2
    rc=1
  else
    echo "PASS: missing tag rejected"
  fi

  echo
  echo "== self-test: signed annotated tag must be accepted =="
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "SKIP: ssh-keygen not available; signed path not exercised"
  else
    local key="$tmp/id_ed25519" signers="$tmp/allowed_signers"
    ssh-keygen -q -t ed25519 -N "" -C "release-gate-selftest@example.invalid" -f "$key"
    printf 'release-gate-selftest@example.invalid %s\n' "$(cat "$key.pub")" > "$signers"
    git -C "$repo" config gpg.format ssh
    git -C "$repo" config user.signingkey "$key.pub"
    git -C "$repo" config gpg.ssh.allowedSignersFile "$signers"
    git -C "$repo" tag -s -a v0.0.2 -m "signed self-test tag"
    if "$SELF" v0.0.2 "$repo"; then
      echo "PASS: signed tag accepted"
    else
      echo "FAIL: signed tag was rejected" >&2
      rc=1
    fi
  fi

  trap - EXIT
  rm -rf "$tmp"
  return "$rc"
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  --self-test)
    self_test
    exit $?
    ;;
  "")
    usage >&2
    exit 2
    ;;
esac

if [ "$#" -gt 2 ]; then
  usage >&2
  exit 2
fi

TAG="$1"
REPO="${2:-}"
if [ -z "$REPO" ]; then
  REPO="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi
if [ ! -d "$REPO" ]; then
  echo "ERROR: repository path '$REPO' is not a directory" >&2
  exit 2
fi

verify_tag "$REPO" "$TAG"
