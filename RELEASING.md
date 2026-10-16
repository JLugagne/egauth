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
2. Run `GOWORK=off go test -timeout 40m ./...` and `make check` locally on a clean checkout. The full journey matrix takes about 15 minutes, so it needs an explicit `-timeout`. `make journey-full` and the CI journey jobs pass one; `make test` and the CI core job exclude `internal/journeytest` and pass their own `-timeout`.
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

Stage and commit the CHANGELOG, go.mod and version-pin changes (the `VERSION` bump and its synced
pins are described in the multi-module section below):

```sh
git add CHANGELOG.md go.mod VERSION adapters/*/go.mod scripts/consumer-smoke.sh
git commit -m "chore: prepare release vX.Y.Z"
```

---

## Step 4 — Generate an SBOM (Software Bill of Materials)

Generate a Software Bill of Materials (SBOM) in CycloneDX format. This documents all dependencies
and their versions, critical for supply-chain transparency and vulnerability tracking:

```sh
# Preferred: the Makefile target installs the pinned syft and emits both formats.
make sbom VERSION=vX.Y.Z

# Manual equivalent. syft v1.x scans a directory, not a module path, so resolve the
# published module to its cache directory first. The main package is cmd/syft — keep
# the version in sync with SYFT_VERSION in the Makefile.
go install github.com/anchore/syft/cmd/syft@v1.54.0
dir="$(GOWORK=off go list -m -f '{{.Dir}}' github.com/JLugagne/egauth@vX.Y.Z)"
syft "dir:$dir" --source-name github.com/JLugagne/egauth --source-version vX.Y.Z \
  -o cyclonedx-json > libauth-vX.Y.Z.sbom.json
syft "dir:$dir" --source-name github.com/JLugagne/egauth --source-version vX.Y.Z \
  -o cyclonedx > libauth-vX.Y.Z.sbom.xml
```

To update the pinned syft version, run `go list -m -versions github.com/anchore/syft`, review the
upstream release notes, then bump `SYFT_VERSION` in the Makefile and the version above together.

Verify the SBOM is generated and contains an entry for each direct and transitive dependency.
Attach both JSON and XML versions to the GitHub Release (Step 6).

---

## Step 5 — Sign and verify the release tag

The **current (v0.13.0+) mechanism is SSH signing** with a dedicated signing-only key
(ed25519); keyless Sigstore via [gitsign](https://github.com/sigstore/gitsign) (OIDC) and
OpenPGP are supported alternatives. Regardless of the mechanism, a release tag is accepted only
when `scripts/verify-release-tag.sh <tag>` passes, which requires `git verify-tag <tag>` to
succeed against the annotated tag object.

### Current: SSH signing (v0.13.0+)

Release tags are signed with a dedicated ed25519 key that is **never used for repository
access**:

- private key: `~/.ssh/egauth-release-signing`
- public key: `~/.ssh/egauth-release-signing.pub` (key comment `egauth-release-signing`)
- fingerprint: `SHA256:oK1EJt+R7t7JbG7TD03LKonWiyrZZ/giuN2ZjqevhL8`

One-time setup (add a passphrase with `ssh-keygen -p -f ~/.ssh/egauth-release-signing`; the
commands below assume the key is loaded, e.g. via `ssh-agent`):

```sh
ssh-keygen -t ed25519 -C "egauth-release-signing" -f ~/.ssh/egauth-release-signing -N ""
git config gpg.format ssh
git config user.signingkey ~/.ssh/egauth-release-signing.pub

# Allow-list the key locally so `git verify-tag` (and the gate) accept it. The principal is the
# tag's tagger identity, not the key comment.
printf '%s %s\n' "<tagger-identity>" "$(cat ~/.ssh/egauth-release-signing.pub)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

Sign, gate and push:

```sh
git tag -s -a vX.Y.Z -m "Release vX.Y.Z"
scripts/verify-release-tag.sh vX.Y.Z    # release gate — must pass before pushing
git push origin vX.Y.Z
```

Publish the public key (the `.pub` contents) in the release notes and/or
[SECURITY.md](SECURITY.md#verifying-a-release) so consumers can verify offline; the SSH
signature itself embeds only the public key and its comment — no email address. To register the
key with GitHub (for the "Verified" badge), add it as a **signing key** under Settings → SSH and
GPG keys; the API equivalent is `POST /user/ssh_signing_keys`.

### Alternative: keyless Sigstore (gitsign)

One-time setup (maintainer machine and, to verify, consumer machines):

```sh
# Install gitsign. Pinned: it produces the signature consumers verify the tag against, so it runs
# with your OIDC identity — never install it at @latest. Keep the version in sync with
# GITSIGN_VERSION in the Makefile, which is the single home for the pin.
go install github.com/sigstore/gitsign@v0.17.1   # or: brew install gitsign

git config --global gpg.x509.program gitsign
git config --global gpg.format x509
```

Create the signed, annotated tag. gitsign opens a browser for the OIDC flow:

```sh
git tag -s -a vX.Y.Z -m "Release vX.Y.Z"
scripts/verify-release-tag.sh vX.Y.Z    # release gate — must pass before pushing
git push origin vX.Y.Z
```

Consumers verify the signature and, separately, the signer identity:

```sh
git verify-tag vX.Y.Z
gitsign verify \
  --certificate-identity=<maintainer-identity> \
  --certificate-oidc-issuer=https://github.com/login/oauth \
  vX.Y.Z
```

`git verify-tag` proves the tag content was signed by the certificate embedded in the tag and
recorded in the Sigstore transparency log; it does not check *who* the signer is, hence the
additional `gitsign verify` identity check. The exact `--certificate-identity` for a release is
recorded in its GitHub release notes. Keyless verification uses the local Sigstore trust root;
the first run may need network access to refresh it, after which verification works offline.

### Alternative: OpenPGP (or a different SSH key)

OpenPGP:

```sh
gpg --list-secret-keys                       # find the release key fingerprint
git config --global gpg.format openpgp
git config --global user.signingkey <FINGERPRINT>
git tag -s -a vX.Y.Z -m "Release vX.Y.Z"
scripts/verify-release-tag.sh vX.Y.Z
git push origin vX.Y.Z
```

Publish the armored public key in the release notes (`gpg --armor --export <FINGERPRINT>`).
Consumers import it and run `git verify-tag vX.Y.Z`.

SSH:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git tag -s -a vX.Y.Z -m "Release vX.Y.Z"
scripts/verify-release-tag.sh vX.Y.Z
git push origin vX.Y.Z
```

Consumers must allow the signing key before `git verify-tag` will trust the tag:

```sh
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
echo '<identity> ssh-ed25519 AAAA...' >> ~/.config/git/allowed_signers
git verify-tag vX.Y.Z
```

Signed tags are recorded in the repository history and serve as a tamper-evident record
of the release date, author, and message.

> **Unsigned tags before the gate.** Tags up to and including `v0.12.0` are **unsigned**
> (`v0.12.0` is a lightweight tag and the `adapters/*/v0.12.0` tags are annotated but unsigned;
> earlier tags, including every `adapters/pgx` tag — `adapters/pgx/v0.6.1` is also lightweight —
> predate this control): `git verify-tag` fails on them. They cannot be signed retroactively.
> Treat them as unverified; the first signed release is `v0.13.0`. Verification instructions are
> in [SECURITY.md](SECURITY.md#verifying-a-release).

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

## Step 7 — Attest the release artifacts

The SBOM files are release artifacts just like the source tag; sign or attest them so a
consumer can verify they were published by the same identity. The choice is the maintainer's;
both consumer verification commands are documented below.

### Option A — keyless cosign (available today)

```sh
# Install cosign. Pinned for the same reason as gitsign: it signs the SBOM release assets.
# COSIGN_VERSION in the Makefile is the source (checked by sync-versions.sh).
go install github.com/sigstore/cosign/v3/cmd/cosign@v3.1.3

cosign sign-blob --yes \
  --bundle libauth-vX.Y.Z.sbom.json.sigstore.json \
  libauth-vX.Y.Z.sbom.json
cosign sign-blob --yes \
  --bundle libauth-vX.Y.Z.sbom.xml.sigstore.json \
  libauth-vX.Y.Z.sbom.xml

# Attach the signature bundles next to the SBOMs.
gh release upload vX.Y.Z \
  libauth-vX.Y.Z.sbom.json.sigstore.json \
  libauth-vX.Y.Z.sbom.xml.sigstore.json
```

Consumers verify an artifact against the signer identity:

```sh
cosign verify-blob \
  --bundle libauth-vX.Y.Z.sbom.json.sigstore.json \
  --certificate-identity=<maintainer-identity> \
  --certificate-oidc-issuer=https://github.com/login/oauth \
  libauth-vX.Y.Z.sbom.json
```

### Option B — GitHub artifact attestations (recommended once the repository is public)

GitHub serves artifact attestations for private repositories only on GitHub Enterprise Cloud,
so this is only available once the repository is public. It is **wired in** as
[`.github/workflows/attest-release.yml`](.github/workflows/attest-release.yml): triggered on
`release: [published]` with `id-token: write` and `attestations: write`, it regenerates the SBOM
for the tagged module (resolved from the proxy) with the pinned syft version, attests it with
[`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
(`subject-path: libauth-*.sbom.*`), and re-uploads the SBOMs so the attested bytes are the ones
a consumer downloads. Use `workflow_dispatch` with a `tag` input to (re)attest an existing
release. Consumers then verify with the GitHub CLI:

```sh
gh attestation verify libauth-vX.Y.Z.sbom.json --repo JLugagne/egauth
```

---

## Multi-module release: core + `adapters/pgx` + `adapters/otel`

The repository is a **multi-module monorepo** with three published modules and one unpublished one:

| Module | Path | Published |
|---|---|---|
| core | `github.com/JLugagne/egauth` | yes, tag `vX.Y.Z` |
| pgx adapter | `github.com/JLugagne/egauth/adapters/pgx` | yes, tag `adapters/pgx/vX.Y.Z` |
| otel adapter | `github.com/JLugagne/egauth/adapters/otel` | yes, tag `adapters/otel/vX.Y.Z` |
| tools (architecture and doc guards) | `github.com/JLugagne/egauth/tools` | no: the tools module is unpublished, never tagged, and excluded from every version pin |

Each published module is versioned and tagged independently, and both adapters depend on core, so
the core tag must be cut **first**. The core module has no dependency on any adapter.

For local development and CI each adapter `go.mod` carries `replace github.com/JLugagne/egauth =>
../..` and a `require` of the core module at `v$(cat VERSION)` (for example `v0.17.0-dev`). A
committed `go.work` lists all four modules. Both are **development-only**: `go.work` is never seen
by external consumers, and each adapter drops its `replace` at release. A shipped `replace` is
ignored by importers, but it is only benign while the matching `require` names a real published
version. `go.work.sum` is a derived lock file and is not tracked.

### Version sync and consumer smoke (verify before every tag)

`VERSION` is the single source of truth. `bash scripts/sync-versions.sh --check` fails when any
adapter `require` of core or `CORE_VERSION` in `scripts/consumer-smoke.sh` differs from it, when a
`go.mod` comment mentions `replace` while that file has none, or when this document stops naming a
published module or the unpublished tools module. Run `bash scripts/sync-versions.sh` without
`--check` to rewrite the pins after bumping `VERSION`. It also fails when the core `go.mod`
requires an adapter, or when one adapter requires the other: the published modules form a tree
with core at the root, and a stale sibling `require` would reintroduce the import cycle.

`bash scripts/consumer-smoke.sh` builds a throwaway consumer that requires all three published
modules, resolves every third-party dependency offline from a file proxy, and runs `go build ./...`
and then `go vet` on one named package per published module (`adapters/otel`,
`adapters/pgx/pgxstore`, `event`); the packages are named because `go vet` reports nothing for
dependencies of the package it is given.

### Adapter granularity convention

There is **one adapter module per backend technology**, not one per domain. `adapters/pgx` holds
all ten pgx stores (`adapters/pgx/store/identity`, `.../store/...`) because they all share the
same `jackc/pgx/v5` driver — a module per domain would mean ten tags to cut for zero
dependency-graph win. A future SQL or Mongo backend gets its **own** module (`adapters/sql`, `adapters/mongo`) so a
consumer who picks pgx never inherits another backend's driver.

### The two-tag release dance (ordered, maintainer-manual)

1. **Cut the core tag first** (Steps 1–5 above): `vX.Y.Z`. Before Step 3, write `X.Y.Z` into
   `VERSION`, run `bash scripts/sync-versions.sh` to rewrite the adapter `require` lines and
   `CORE_VERSION`, then `bash scripts/sync-versions.sh --check` and `bash scripts/consumer-smoke.sh`.
   Stage `VERSION`, `adapters/*/go.mod` and `scripts/consumer-smoke.sh` together with the Step 3
   files. An adapter's `require` can only point at a published core version, so core must exist on
   the proxy before any adapter is tagged.
2. **Point each adapter at the published core version** (repeat for `adapters/otel`). Pre-tag, `adapters/pgx/go.mod` pins the core
   `require` and carries the dev `replace github.com/JLugagne/egauth => ../..`. Now that core is
   published, drop the replace, pin the require to the freshly-cut version, and regenerate `go.sum`
   against the proxy (`GOWORK=off` forces proxy resolution instead of the workspace):

   ```sh
   cd adapters/pgx
   go mod edit -dropreplace=github.com/JLugagne/egauth -require=github.com/JLugagne/egauth@vX.Y.Z
   sed -i.bak '/^\/\/ The `replace` below/,/^\/\/ against the published core tag/d' go.mod && rm go.mod.bak
   GOWORK=off go mod tidy   # resolves core from the proxy; proves the adapter builds standalone
   cd ../..
   bash scripts/sync-versions.sh --check
   git add adapters/pgx/go.mod adapters/pgx/go.sum
   git commit -m "chore: point adapters/pgx at egauth vX.Y.Z"
   ```

   The `sed` line deletes the development comment that explains the `replace`;
   `sync-versions.sh --check` rejects a comment that mentions a `replace` the file no longer has.

   A `replace` left in the shipped go.mod is ignored by external importers, but it is only benign
   while the matching `require` names a real published version — do not treat it as harmless by
   default and do not leave a placeholder behind. Dropping it keeps the published module clean.
3. **Cut the adapter tags** (`adapters/pgx/vX.Y.Z` and `adapters/otel/vX.Y.Z`), which is path-prefixed because it is a nested module. Like the
   core tag it must be annotated and signed, and it must pass the release gate before it is
   pushed:

   ```sh
   git tag -s -a adapters/pgx/vX.Y.Z -m "adapters/pgx vX.Y.Z"
   scripts/verify-release-tag.sh adapters/pgx/vX.Y.Z
   git push origin adapters/pgx/vX.Y.Z
   ```
4. **Consumers** then install each module at its tag, independently:

   ```sh
   go get github.com/JLugagne/egauth@vX.Y.Z
   go get github.com/JLugagne/egauth/adapters/pgx@vX.Y.Z
   go get github.com/JLugagne/egauth/adapters/otel@vX.Y.Z
   ```

5. **Return to development.** After the tags are pushed, write the next `X.Y.Z-dev` into
   `VERSION`, restore the development `replace` in each adapter
   (`go mod edit -replace=github.com/JLugagne/egauth=../..`), run `bash scripts/sync-versions.sh`
   and commit, so `main` builds from the checkout again.

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
- Require status checks to pass. Name these explicitly, so "does the vulnerability scan gate
  merges?" is answerable by reading this file rather than by inspecting the UI:
  **Vulnerability Check (all modules)**, **Linting (all modules)**,
  **Fuzz (short pass on untrusted-input parsers)**, **Core — Test & Vet (ubuntu-latest, no Docker)**, **Core — Test & Vet (macos-latest, no Docker)**,
  **Core — Test & Vet (windows-latest, no Docker)**, **Docker-less unit tests (go test -short)**,
  **Doc lint (tools/doclint)**, **Architecture guards (tools/archtest)**, **Version sync (G17)**,
  **Journey matrix (short)**, **Journey matrix (full) and G7b**,
  **adapters/pgx — Test & Vet (Docker/testcontainers)**, **Test adapters/otel** and
  **Packaging — consumer module graph (offline)**.
- Require conversation resolution before merging
- Do not allow force pushes

---

## Tag protection and the release gate

A pushed tag is served by the Go module proxy as soon as it is pushed, when the first consumer
requests it. **Nothing can gate that after the fact**, so the control that matters is who may create
a tag at all.

GitHub → Settings → Rules → New ruleset, targeting `refs/tags/v*` and
`refs/tags/adapters/*/v*`:

- Restrict creations, updates and deletions to the maintainer (bypass list empty)
- Block force pushes

`.github/workflows/release-verify.yml` runs `scripts/verify-release-tag.sh` on every tag push as a
**detector**: it reports an unsigned or lightweight tag immediately instead of letting it pass
unnoticed, and `workflow_dispatch` lets you verify an existing tag. It cannot prevent publication —
by the time it runs, the tag may already be resolvable.

Set the repository secret **`RELEASE_SIGNING_PUBKEY`** to the `allowed_signers` line for the release
key (see "Verifying a release" in `SECURITY.md`) so the gate can verify SSH or OpenPGP signatures.
Without it the gate can only verify keyless Sigstore tags and will say so. The key is a secret rather
than a committed file on purpose: anyone able to push to the default branch could otherwise replace a
committed trusted key and the gate would accept their signature.

---

## Release checklist summary

Before pushing a new release, ensure all steps below are complete:

- [ ] **Pre-release verification**: Confirm `main` is green in CI, run local `GOWORK=off go test -timeout 40m ./...` and `make check`
- [ ] **CHANGELOG updated**: Move `[Unreleased]` section to a dated version header (`## [vX.Y.Z] — YYYY-MM-DD`)
- [ ] **go.mod retract block**: Add `retract` directive for any pre-release or yanked versions (if applicable)
- [ ] **Versions in sync**: `bash scripts/sync-versions.sh --check` passes and `bash scripts/consumer-smoke.sh` builds and vets one package per published module
- [ ] **Changes committed**: Stage and commit CHANGELOG.md, go.mod, VERSION, adapters/*/go.mod and scripts/consumer-smoke.sh with message "chore: prepare release vX.Y.Z"
- [ ] **SBOM generated**: Run `syft` to generate SBOM in both JSON and XML format
- [ ] **Tag signed**: Create a signed, annotated tag with `git tag -s -a vX.Y.Z -m "Release vX.Y.Z"` using the identity model in Step 5 (SSH is current; gitsign keyless or OpenPGP are alternatives)
- [ ] **Tag gate passed**: `bash scripts/verify-release-tag.sh vX.Y.Z` exits 0 against the local tag; do not push a tag the gate rejects
- [ ] **Tag pushed**: Push the signed tag with `git push origin vX.Y.Z`
- [ ] **GitHub release created**: Use `gh release create` with CHANGELOG notes; record the signer's `--certificate-identity` and the `scripts/verify-release-tag.sh` output in the notes
- [ ] **SBOM attached**: Upload SBOM JSON and XML files to the GitHub release
- [ ] **Artifacts attested**: the `attest-release.yml` workflow attests the SBOMs on `release: [published]` (Step 7 Option B); for a release cut before it ran, use `workflow_dispatch` with the tag (or keyless cosign, Step 7 Option A)
- [ ] **Adapter tags (if applicable)**: For multi-module releases, cut the signed adapter tags after the core tag is published and gate each with `bash scripts/verify-release-tag.sh adapters/pgx/vX.Y.Z` and `adapters/otel/vX.Y.Z`

### Vulnerability gate

Before releasing, verify that:
- [ ] `govulncheck ./...` passes with no unresolved vulnerabilities
- [ ] `govulncheck` passes in `adapters/pgx` and `adapters/otel` (if releasing adapters)

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

The packages covered by the promise, and the ones that are explicitly experimental, are listed
in [docs/adr/0001-v1-scope-and-stability-classes.md](docs/adr/0001-v1-scope-and-stability-classes.md).

---

## v1 API-freeze review checklist

Run this before tagging v1.0.0, and re-run the relevant parts before any change to a
`frozen-v1` package. The goal is that the SemVer promise covers a surface that is named
deliberately, reviewed for security defaults, and able to grow without breaking implementers.

### Naming and stability

- [ ] Every exported identifier in a `frozen-v1` package is named for its final meaning; no
      temporary, internal or placeholder names survive the freeze.
- [ ] A `go doc -all` sweep per frozen package was reviewed against the stability table, and each
      package doc carries its stability class.
- [ ] New exported surface is either part of the frozen contract or explicitly marked
      `// Experimental:`; nothing is added silently.
- [ ] No `frozen-v1` exported signature exposes an experimental package's type in a way that
      would freeze it transitively. If it does, promote the type or change the signature before
      the tag.
- [ ] Options follow the `WithX` convention, and every opt-out that weakens a security default is
      named `WithInsecure*` or `Insecure*` and documented as a risk.

### Security-relevant options

- [ ] Every exported option and `Config` field was reviewed for security impact and defaults to
      the safe behavior.
- [ ] A test fails if a secure default flips silently (same-origin gate, cookie flags, token
      length, lockout, OTP/TOTP attempt limits, challenge store, state signing key).
- [ ] Secret-bearing types keep their `fmt`/`slog` redaction, and no exported type adds a secret
      field without it.
- [ ] Sensitive comparisons on the authentication path are constant-time or explicitly documented
      as not requiring it.

### Store interface growth

- [ ] Each core `Store` interface is segmented into a stable core plus optional capability
      interfaces; adding a capability in v1.x adds a new interface, never a method to a frozen
      one.
- [ ] Adding a method to a `frozen-v1` interface is treated as a breaking change: it is deferred
      to the next major version or shipped as a new optional interface.
- [ ] Every new optional interface has a conformance suite (`*/storetest` or the equivalent
      exported contract helper), and every bundled backend passes it.
- [ ] Concurrency-critical methods (single-use consumption, compare-and-set, atomic counters)
      remain documented as such, and their contract tests still assert the atomic behavior.

---

## Deprecation policy

- **Announce before removing.** An exported symbol in a `frozen-v1` package is marked
  `// Deprecated: <reason>. Use <replacement> instead.`, documented in `CHANGELOG.md`, and left
  working for at least one minor release before it is removed in the next major version.
- **Removal only in a major.** Within v1.x, a deprecated symbol keeps compiling and working; its
  removal requires a new module major (`.../v2`).
- **Safety wins over the compatibility promise.** A symbol that cannot be made safe is the one
  exception: it may be disabled or removed in a minor or patch release, with the reason recorded
  in `CHANGELOG.md` and `SECURITY.md`.
- **Retract unusable releases.** A published version that must not be used is handled with a
  `retract` directive in `go.mod` (see "Step 2 — Update `retract` in go.mod").
- **Experimental packages are exempt.** They may change or be removed in any release without a
  major-version bump; the change is still called out in `CHANGELOG.md`.
- **Update the stability docs.** When a package is deprecated or removed, update the stability
  table in the ADR and the package's godoc in the same change.
