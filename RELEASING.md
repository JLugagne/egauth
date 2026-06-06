# Releasing libauth

This document describes the manual steps a maintainer takes to cut a new release.
Tagging and flipping the repository public are **deliberate manual actions** — they are
not automated by CI.

---

## Ground truth: published-tag baseline

The remote (`github.com/JLugagne/egauth`) already serves the following tags.
All were pushed **before the security hardening** introduced in Milestone 1:

| Tag     | Commit    | Notes                                          |
|---------|-----------|------------------------------------------------|
| v0.1.0  | —         | Initial public release, pre-hardening          |
| v0.2.0  | bea19c2   | Pre-hardening; identical tree to v0.2.1        |
| v0.2.1  | bea19c2   | Pre-hardening; same commit as v0.2.0           |

**Always use the remote tags as ground truth** when deciding what to retract or what
the next version number should be.  Do not rely solely on local tags.

---

## Pre-release checklist

1. Confirm `main` is green (all CI checks pass).
2. Run `go test ./...` and `make check` locally on a clean checkout.
3. Review open issues and PRs — defer anything that should not ship.

---

## Step 1 — Update CHANGELOG.md

Move the `[Unreleased]` section to a dated version header:

```markdown
## [vX.Y.Z] — YYYY-MM-DD
```

Update the comparison link at the bottom of CHANGELOG.md so it points to the new tag.

---

## Step 2 — Update `retract` in go.mod

If this release supersedes any pre-release or yanked version, add a `retract` directive
to `go.mod`:

```go
retract (
    v0.1.0 // pre-hardening — do not use
    v0.2.0 // pre-hardening — do not use
    v0.2.1 // pre-hardening — do not use
)
```

The `retract` block takes effect only after the new tag is pushed; the Go module proxy
will surface the retraction notice to users of the old versions.

---

## Step 3 — Commit the release preparation

Stage and commit the CHANGELOG and go.mod changes:

```sh
git add CHANGELOG.md go.mod
git commit -m "chore: prepare release vX.Y.Z"
```

---

## Step 4 — Create an annotated tag

Annotated tags (not lightweight tags) are the correct form for Go module releases because
they carry author, date, and message metadata:

```sh
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

Pushing the tag makes the release visible to `go get` and triggers the Go module proxy to
index the new version.

---

## Step 5 — Create the GitHub Release

```sh
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <(awk '/^## \[vX\.Y\.Z\]/,/^## \[/' CHANGELOG.md | head -n -1)
```

Or create the release manually in the GitHub UI, pasting the relevant CHANGELOG section.

---

## Multi-module release: core + `adapters/pgx`

The repository is a **multi-module monorepo**: the core flagship module
(`github.com/JLugagne/egauth`) and a nested pgx adapter module
(`github.com/JLugagne/egauth/adapters/pgx`, holding the PostgreSQL stores + migration runner).
Each module is versioned and tagged independently, and the adapter depends on core — so the two
tags must be cut **in order**.

For local development and CI, the adapter `go.mod` carries a relative `replace
github.com/JLugagne/egauth => ../..` that resolves the (as-yet-unpublished, private) core module
from this repo's root, so every go command — `build`, `test`, `vet`, `tidy`, `go work sync` — works
offline without reaching the proxy for a core version that doesn't exist yet. A committed `go.work`
also lists both modules so the workspace spans them. Both are **development-only**: `go.work` is
never seen by external consumers, and the `replace` is dropped at release (and is ignored by
importers even if it shipped). `go.work.sum` is a derived lock file and is not tracked.

### Adapter granularity convention

There is **one adapter module per backend technology**, not one per domain. `adapters/pgx` holds
all seven pgx stores (`adapters/pgx/identity`, `.../tokens`, …) because they all share the same
`jackc/pgx/v5` driver — a module per domain would mean seven tags to cut for zero dependency-graph
win. A future SQL or Mongo backend gets its **own** module (`adapters/sql`, `adapters/mongo`) so a
consumer who picks pgx never inherits another backend's driver.

### The two-tag release dance (ordered, maintainer-manual)

1. **Cut the core tag first** (Steps 1–5 above): `vX.Y.Z`. The adapter's `require` can only point at
   a published core version, so core must exist on the proxy before the adapter is tagged.
2. **Point the adapter at the published core version.** Pre-tag, `adapters/pgx/go.mod` pins the core
   `require` and carries the dev `replace github.com/JLugagne/egauth => ../..`. Now that core is
   published, drop the replace, pin the require to the freshly-cut version, and regenerate `go.sum`
   against the proxy (`GOWORK=off` forces proxy resolution instead of the workspace):

   ```sh
   cd adapters/pgx
   go mod edit -dropreplace=github.com/JLugagne/egauth -require=github.com/JLugagne/egauth@vX.Y.Z
   GOWORK=off go mod tidy   # resolves core from the proxy; proves the adapter builds standalone
   cd ..
   git add adapters/pgx/go.mod adapters/pgx/go.sum
   git commit -m "chore: point adapters/pgx at egauth vX.Y.Z"
   ```

   A `replace` left in the shipped go.mod is ignored by external importers (so it's harmless if
   forgotten), but dropping it keeps the published module clean.
3. **Cut the adapter tag**, which is path-prefixed because it is a nested module:

   ```sh
   git tag -a adapters/pgx/vX.Y.Z -m "adapters/pgx vX.Y.Z"
   git push origin adapters/pgx/vX.Y.Z
   ```
4. **Consumers** then install each module at its tag, independently:

   ```sh
   go get github.com/JLugagne/egauth@vX.Y.Z
   go get github.com/JLugagne/egauth/adapters/pgx@vX.Y.Z
   ```

The core and adapter versions need not match, but keeping them in lockstep (same `vX.Y.Z`) is the
simplest mental model while the adapter tracks core 1:1.

---

## Flipping the repository public

When the repository is ready to go public, the maintainer performs this step **manually**
in GitHub → Settings → Danger Zone → "Change repository visibility".  There is no
automated or scripted path for this action.

---

## Branch protection on `main`

Branch protection rules are a **GitHub repository-settings** action, not a file in the
repository.  After going public, configure protection via:

GitHub → Settings → Branches → Add branch protection rule for `main`:

- Require a pull request before merging
- Require status checks to pass (select the CI jobs)
- Require conversation resolution before merging
- Do not allow force pushes

---

## Versioning policy

libauth follows [Semantic Versioning](https://semver.org/):

- **Patch** (vX.Y.Z → vX.Y.Z+1): bug fixes with no API change.
- **Minor** (vX.Y.Z → vX.Y+1.0): backwards-compatible new features or additions.
- **Major** (vX.Y.Z → vX+1.0.0): breaking API changes; requires updating the module path
  (e.g. `github.com/JLugagne/egauth/v2`).
