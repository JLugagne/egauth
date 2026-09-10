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
# Install syft if not already present (https://github.com/anchore/syft).
# Pinned to an exact version — keep in sync with SYFT_VERSION in the Makefile.
go install github.com/anchore/syft@v1.51.1

# Generate SBOM from the module and save to the release directory
syft -o cyclonedx-json github.com/JLugagne/egauth@vX.Y.Z > libauth-vX.Y.Z.sbom.json
syft -o cyclonedx github.com/JLugagne/egauth@vX.Y.Z > libauth-vX.Y.Z.sbom.xml
```

To update the pinned syft version, run `go list -m -versions github.com/anchore/syft`, review the
upstream release notes, then bump `SYFT_VERSION` in the Makefile and the version above together.

Verify the SBOM is generated and contains an entry for each direct and transitive dependency.
Attach both JSON and XML versions to the GitHub Release (Step 6).

---

## Step 5 — Sign and verify the release tag

The release identity model is **keyless Sigstore signing via
[gitsign](https://github.com/sigstore/gitsign) (OIDC)**. OpenPGP and SSH signing are supported
alternatives. Regardless of the mechanism, a release tag is accepted only when
`scripts/verify-release-tag.sh <tag>` passes, which requires `git verify-tag <tag>` to succeed
against the annotated tag object.

### Primary: keyless Sigstore (gitsign)

One-time setup (maintainer machine and, to verify, consumer machines):

```sh
# Install gitsign (pin a version you have reviewed; `latest` is shown for brevity).
go install github.com/sigstore/gitsign@latest   # or: brew install gitsign

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

### Alternative: OpenPGP or SSH

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

> **Unsigned tags before the gate.** Release tags up to and including `v0.11.0`, including all
> `adapters/pgx` tags, are **unsigned** (`adapters/pgx/v0.6.1` is even a lightweight tag):
> `git verify-tag` fails on them. They predate this gate and cannot be signed retroactively.
> Treat them as unverified and prefer the first signed release; verification instructions are
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
# Install cosign (pin a version you have reviewed; `latest` is shown for brevity).
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

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
so this is a **maintainer step to enable when the repository goes public**, not a wired-in
workflow today. Once public, add a workflow triggered on `release: [published]` with
`id-token: write` and `attestations: write` that checks out the tag, regenerates the SBOM with
the pinned syft version, and attests it with
[`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
(`subject-path: libauth-*.sbom.*`). Consumers then verify with the GitHub CLI:

```sh
gh attestation verify libauth-vX.Y.Z.sbom.json --repo JLugagne/egauth
```

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
never seen by external consumers, and the adapter drops its `replace` at release. A shipped
`replace` is ignored by importers, but that does **not** make it harmless: it can only be left in
place while the matching `require` names a real published version, because consumers resolve that
`require` themselves. The root module's adapter requirement is the critical case — see below.
`go.work.sum` is a derived lock file and is not tracked.

### Root module `adapters/pgx` requirement (verify before every core tag)

The root `go.mod` requires the adapter because the `e2e-security` tests import
`adapters/pgx/passkey`. External consumers cannot see the root module's local
`replace github.com/JLugagne/egauth/adapters/pgx => ./adapters/pgx`, so the `require` must
always name a version the module proxy can serve. A placeholder left over from local
development (such as the zero pseudo-version `v0.0.0-00010101000000-000000000000`) makes
`go list -m all`, `go mod download all`, and SBOM tooling fail for every consumer even
though `go build` of imported packages still succeeds.

Before tagging core, confirm the pinned adapter version is published and that the consumer
module commands succeed offline against a local file proxy:

```sh
# The pinned version must be listed by the proxy.
go list -m -versions github.com/JLugagne/egauth/adapters/pgx

# Warm the module cache for the offline consumer check, then run it.
go mod download github.com/JLugagne/egauth/adapters/pgx@vX.Y.Z
bash scripts/consumer-smoke.sh   # asserts consumer `go list -m all` and `go mod download all`
```

The `replace` directive may stay in the repository for development; consumers ignore it,
and the published `require` resolves on its own.

### Adapter granularity convention

There is **one adapter module per backend technology**, not one per domain. `adapters/pgx` holds
all seven pgx stores (`adapters/pgx/identity`, `.../tokens`, …) because they all share the same
`jackc/pgx/v5` driver — a module per domain would mean seven tags to cut for zero dependency-graph
win. A future SQL or Mongo backend gets its **own** module (`adapters/sql`, `adapters/mongo`) so a
consumer who picks pgx never inherits another backend's driver.

### The two-tag release dance (ordered, maintainer-manual)

1. **Cut the core tag first** (Steps 1–5 above): `vX.Y.Z`. First run the root module's adapter-pin
   check (see "Root module `adapters/pgx` requirement" above). The adapter's `require` can only point
   at a published core version, so core must exist on the proxy before the adapter is tagged.
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

   A `replace` left in the shipped go.mod is ignored by external importers, but it is only benign
   while the matching `require` names a real published version — do not treat it as harmless by
   default and do not leave a placeholder behind. Dropping it keeps the published module clean.
3. **Cut the adapter tag**, which is path-prefixed because it is a nested module. Like the
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

## Release checklist summary

Before pushing a new release, ensure all steps below are complete:

- [ ] **Pre-release verification**: Confirm `main` is green in CI, run local `go test ./...` and `make check`
- [ ] **CHANGELOG updated**: Move `[Unreleased]` section to a dated version header (`## [vX.Y.Z] — YYYY-MM-DD`)
- [ ] **go.mod retract block**: Add `retract` directive for any pre-release or yanked versions (if applicable)
- [ ] **Root adapter pin verified**: Root go.mod requires a published `adapters/pgx` version (no placeholder); `go list -m all` and `go mod download all` pass via `bash scripts/consumer-smoke.sh`
- [ ] **Changes committed**: Stage and commit CHANGELOG.md and go.mod with message "chore: prepare release vX.Y.Z"
- [ ] **SBOM generated**: Run `syft` to generate SBOM in both JSON and XML format
- [ ] **Tag signed**: Create a signed, annotated tag with `git tag -s -a vX.Y.Z -m "Release vX.Y.Z"` using the identity model in Step 5 (gitsign keyless, or OpenPGP/SSH)
- [ ] **Tag gate passed**: `bash scripts/verify-release-tag.sh vX.Y.Z` exits 0 against the local tag; do not push a tag the gate rejects
- [ ] **Tag pushed**: Push the signed tag with `git push origin vX.Y.Z`
- [ ] **GitHub release created**: Use `gh release create` with CHANGELOG notes; record the signer's `--certificate-identity` and the `scripts/verify-release-tag.sh` output in the notes
- [ ] **SBOM attached**: Upload SBOM JSON and XML files to the GitHub release
- [ ] **Artifacts attested**: Sign the SBOM bundles with keyless cosign (Step 7 Option A) or attest them via GitHub artifact attestations once public (Option B), and upload the bundles
- [ ] **Adapter tag (if applicable)**: For multi-module releases, cut the signed adapter tag after the core tag is published and gate it with `bash scripts/verify-release-tag.sh adapters/pgx/vX.Y.Z`

### Vulnerability gate

Before releasing, verify that:
- [ ] `govulncheck ./...` passes with no unresolved vulnerabilities
- [ ] `govulncheck ./adapters/pgx/...` passes (if releasing adapters)

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
