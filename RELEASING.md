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

## Step 4 — Generate an SBOM (Software Bill of Materials)

Generate a Software Bill of Materials (SBOM) in CycloneDX format. This documents all dependencies
and their versions, critical for supply-chain transparency and vulnerability tracking:

```sh
# Install syft if not already present (https://github.com/anchore/syft)
go install github.com/anchore/syft@latest

# Generate SBOM from the module and save to the release directory
syft -o cyclonedx-json github.com/JLugagne/egauth@vX.Y.Z > libauth-vX.Y.Z.sbom.json
syft -o cyclonedx github.com/JLugagne/egauth@vX.Y.Z > libauth-vX.Y.Z.sbom.xml
```

Verify the SBOM is generated and contains an entry for each direct and transitive dependency.
Attach both JSON and XML versions to the GitHub Release (Step 6).

---

## Step 5 — Sign the release tag with GPG

Before creating the tag, ensure your GPG key is configured:

```sh
# List your GPG keys (choose the one you want to use for releases)
gpg --list-keys

# Configure git to sign tags with your key (optional, if not already set)
git config user.signingkey <KEY_ID>
```

Create a signed (GPG-annotated) tag. This adds cryptographic assurance that the tag was
created by you:

```sh
git tag -s -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

The `-s` flag signs the tag with your GPG key; `-a` makes it an annotated tag.

**Verification:**
Others can verify the tag signature with:

```sh
git tag -v vX.Y.Z
```

If you are using ephemeral keys or do not have GPG set up, you may alternatively use
[Sigstore/cosign](https://docs.sigstore.dev/):

```sh
# Sign the tag with cosign (requires GITHUB_TOKEN)
cosign sign-blob --key cosign.key vX.Y.Z
```

Signed tags are recorded in the repository history and serve as a tamper-evident record
of the release date, author, and message.

---

## Step 6 — Create the GitHub Release and attach SBOM

Create the GitHub release with the CHANGELOG notes:

```sh
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <(awk '/^## \[vX\.Y\.Z\]/,/^## \[/' CHANGELOG.md | head -n -1)
```

Then attach the SBOM files to the release:

```sh
gh release upload vX.Y.Z libauth-vX.Y.Z.sbom.json libauth-vX.Y.Z.sbom.xml
```

Alternatively, create the release manually in the GitHub UI:
1. Go to Releases and click "Create a new release"
2. Select the tag `vX.Y.Z` (which you just pushed)
3. Paste the relevant CHANGELOG section as the release notes
4. Attach the SBOM files (JSON and XML) as release assets
5. Publish the release

---

## Multi-module release: core + `adapters/pgx` + `adapters/otel`

The repository is a **multi-module monorepo**: the core flagship module
(`github.com/JLugagne/egauth`), a nested pgx adapter module
(`github.com/JLugagne/egauth/adapters/pgx`, holding the PostgreSQL stores + migration runner), and
a nested OpenTelemetry adapter module (`github.com/JLugagne/egauth/adapters/otel`, an `event.Sink`
that emits spans). Each module is versioned and tagged independently, and both adapters depend on
core — so the core tag must be cut **before** either adapter tag.

Local development and CI resolve core from this repo's root via the committed root `go.work`
(`use ( . ./adapters/pgx ./adapters/otel )`), regardless of what each adapter's own `require`/
`replace` says — this is what lets every go command (`build`, `test`, `vet`, `go work sync`) run
against the current, in-tree core with no proxy access. `go.work` is **development-only**: it is
never seen by external consumers. `go.work.sum` is a derived lock file and is not tracked.

The two adapters are currently in different states of the release dance below:

- **`adapters/pgx/go.mod` carries no `replace`.** Its `require` pins core directly at the latest
  published tag (currently `v0.7.0`), exactly as an external importer resolves it — this is the
  **post-Step-2** state described below, reached the last time pgx's `require` was bumped.
- **`adapters/otel/go.mod` still carries `replace github.com/JLugagne/egauth => ../..`.** Its
  `require` pin is bumped in lockstep with pgx's (Step 2 below applies to it too) but the replace
  has not yet been dropped.

A `replace` left in a shipped go.mod is ignored by external importers (so it is harmless either
way); the two adapters do not need to be in the same state as each other, only self-consistent —
whichever state a given adapter is in, `go mod edit -dropreplace=... -require=...@vX.Y.Z` (Step 2)
is what advances it, and `GOWORK=off go build ./...` inside that adapter's directory is what proves
the drop actually resolved from the proxy rather than silently falling back to the workspace.

### Adapter granularity convention

There is **one adapter module per backend technology**, not one per domain. `adapters/pgx` holds
all seven pgx stores (`adapters/pgx/identity`, `.../tokens`, …) because they all share the same
`jackc/pgx/v5` driver — a module per domain would mean seven tags to cut for zero dependency-graph
win. A future SQL or Mongo backend gets its **own** module (`adapters/sql`, `adapters/mongo`) so a
consumer who picks pgx never inherits another backend's driver.

### The release dance (ordered, maintainer-manual)

1. **Cut the core tag first** (Steps 1–5 above): `vX.Y.Z`. Each adapter's `require` can only point
   at a published core version, so core must exist on the proxy before either adapter is tagged.
2. **Point each adapter at the published core version.** For an adapter whose go.mod still carries
   the dev `replace github.com/JLugagne/egauth => ../..` (currently `adapters/otel`), drop it and
   pin the require to the freshly-cut version in one step:

   ```sh
   cd adapters/otel
   go mod edit -dropreplace=github.com/JLugagne/egauth -require=github.com/JLugagne/egauth@vX.Y.Z
   GOWORK=off go mod tidy   # resolves core from the proxy; proves the adapter builds standalone
   cd ..
   git add adapters/otel/go.mod adapters/otel/go.sum
   git commit -m "chore: point adapters/otel at egauth vX.Y.Z"
   ```

   For an adapter that already has no `replace` (currently `adapters/pgx`), just bump the pin:

   ```sh
   cd adapters/pgx
   go mod edit -require=github.com/JLugagne/egauth@vX.Y.Z
   GOWORK=off go mod tidy   # resolves core from the proxy; proves the adapter builds standalone
   cd ..
   git add adapters/pgx/go.mod adapters/pgx/go.sum
   git commit -m "chore: point adapters/pgx at egauth vX.Y.Z"
   ```

   A `replace` left in a shipped go.mod is ignored by external importers (so it's harmless if
   forgotten), but dropping it keeps the published module clean.
3. **Cut each adapter tag**, path-prefixed because each is a nested module:

   ```sh
   git tag -a adapters/pgx/vX.Y.Z -m "adapters/pgx vX.Y.Z"
   git push origin adapters/pgx/vX.Y.Z
   git tag -a adapters/otel/vX.Y.Z -m "adapters/otel vX.Y.Z"
   git push origin adapters/otel/vX.Y.Z
   ```
4. **Consumers** then install each module at its tag, independently:

   ```sh
   go get github.com/JLugagne/egauth@vX.Y.Z
   go get github.com/JLugagne/egauth/adapters/pgx@vX.Y.Z
   go get github.com/JLugagne/egauth/adapters/otel@vX.Y.Z
   ```

The core and adapter versions need not match, but keeping them in lockstep (same `vX.Y.Z`) is the
simplest mental model while both adapters track core 1:1.

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

## Release checklist summary

Before pushing a new release, ensure all steps below are complete:

- [ ] **Pre-release verification**: Confirm `main` is green in CI, run local `go test ./...` and `make check`
- [ ] **CHANGELOG updated**: Move `[Unreleased]` section to a dated version header (`## [vX.Y.Z] — YYYY-MM-DD`)
- [ ] **go.mod retract block**: Add `retract` directive for any pre-release or yanked versions (if applicable)
- [ ] **Changes committed**: Stage and commit CHANGELOG.md and go.mod with message "chore: prepare release vX.Y.Z"
- [ ] **SBOM generated**: Run `syft` to generate SBOM in both JSON and XML format
- [ ] **Tag signed**: Create a signed, annotated tag with `git tag -s -a vX.Y.Z -m "Release vX.Y.Z"` (requires GPG setup)
- [ ] **Tag pushed**: Push the signed tag with `git push origin vX.Y.Z`
- [ ] **GitHub release created**: Use `gh release create` with CHANGELOG notes
- [ ] **SBOM attached**: Upload SBOM JSON and XML files to the GitHub release
- [ ] **Adapter tags (if applicable)**: For multi-module releases, cut the `adapters/pgx` and `adapters/otel` tags after the core tag is published

### Vulnerability gate

Before releasing, verify that:
- [ ] `govulncheck ./...` passes with no unresolved vulnerabilities
- [ ] `govulncheck ./adapters/pgx/...` passes (if releasing adapters)
- [ ] `govulncheck ./adapters/otel/...` passes (if releasing adapters)

### Documentation

- [ ] RELEASING.md is up to date with the current signing and SBOM procedures
- [ ] CHANGELOG.md accurately reflects all changes since the last release
- [ ] README.md versions are accurate and any breaking changes are highlighted

---

## Versioning policy

libauth follows [Semantic Versioning](https://semver.org/):

- **Patch** (vX.Y.Z → vX.Y.Z+1): bug fixes with no API change.
- **Minor** (vX.Y.Z → vX.Y+1.0): backwards-compatible new features or additions.
- **Major** (vX.Y.Z → vX+1.0.0): breaking API changes; requires updating the module path
  (e.g. `github.com/JLugagne/egauth/v2`).
