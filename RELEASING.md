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
