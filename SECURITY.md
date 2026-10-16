# Security model

> **Audit status.** egauth's security review to date is an AI-driven audit only; it has not had
> an independent third-party human security audit, and that risk is accepted for v1.0 — pin a
> reviewed commit, commission your own audit, or wait if that trade-off is unacceptable.
> "AI-audited" is **not** a synonym for "audited". See [AUDIT.md](AUDIT.md) for the full review
> scope (what was reviewed and how, what was not, the accepted trade-offs) and the cautious-user
> escape hatch.

This document describes how `egauth` v0.17 handles secrets and passwords, what the library
guarantees by construction, and what stays with the application. The design principle is that a
mistake an integrator could make should not compile, should make `egauth.New` return an error, or
should be caught by a CI guard (see [CONTRIBUTING.md](CONTRIBUTING.md)). A guarantee below names
the mechanism that holds it.

## Handling secrets and passwords

### Passwords

- **Hashing.** Passwords are hashed with Argon2id (`passwords/argon2`), with the cost and a
  per-hash salt recorded in the stored PHC string. Input is normalised (NFKC) and bounded to 8 to
  1024 characters before the configured policy runs, so an oversized input cannot be used to burn
  hashing time.
- **Constant-time comparison.** Verification compares the derived key with
  `crypto/subtle.ConstantTimeCompare` and never branches on the byte-wise outcome. A malformed
  stored hash is rejected before the KDF, which depends only on the stored value and not on the
  candidate.
- **Decoy hashing.** Every login branch that would skip the real comparison (unknown identifier,
  missing credential, locked, disabled or unverified account) spends an equivalent Argon2id pass on
  a decoy, and charges the lockout counter of a decoy subject. Existence, lock state and
  verification state are therefore not visible in response time or in the response, which is the
  same `invalid_credentials` answer for each. The guarantee is structural: the branches share one
  code path in `internal/identitysvc`.
- **Lockout.** Consecutive failures lock the credential for a window. The threshold and window are
  constants, so no caller can weaken them, and the authenticated change-password path verifies the
  current password under the same policy.
- **Rehash on login.** A hash recorded at an older cost is replaced after a successful login.

### Opaque tokens

Refresh tokens, session handles and API keys are generated from `crypto/rand` and stored only as
hashes, so a database leak does not expose a usable credential.
Lookups run on the hash. Refresh tokens are single use and chained into a family: replay outside the
grace window, or inside it from another client fingerprint, revokes the whole family.

### Sealing at rest

Secrets that must be recoverable (TOTP seeds, OAuth client secrets, tenant signing keys) are sealed
with a `kek.KEK`. Associated data is mandatory on every seal and open, binding a blob to its tenant,
subject and column, so a blob cannot be replayed elsewhere. Sealing is versioned, and `egauth.New`
checks a canary so that a wrong or rotated-out key is a startup error. The memory stores seal
nothing and are refused on a public origin.

Key material is validated by one policy: a minimum length, no all-zero or repeated-byte patterns,
and rejection of published example keys and near copies of them. This applies to the KEK, signing
keys and any other key loaded by the library.

### Logging and redaction

- Credential-bearing types render their secret as `REDACTED` through `fmt` (`%v`, `%+v`, `%#v`) and
  `slog`: `egauth.LinkMessage`, `egauth.CodeMessage`, `egauth.SecurityNoticeMessage`,
  `federation.Secret` and `federation.Provider`. Redaction is a
  backstop against an accidental dump, not a license to log a value.
- JSON encoding is not redacted. A deliverer that queues messages as JSON stores the link, code or
  revert link in clear in that queue, so the queue holds credentials.
- Errors name the cause and non-sensitive metadata, never a plaintext secret.
- Events carry attributes that each declare a sensitivity. Sinks drop personal attributes (IP
  address, user agent, previous email) unless an operator explicitly exports them.

### What the application holds

The application receives plaintext exactly once where a value cannot be recovered later: an API key
secret (`egauth.APIKeySecret`, read with `Reveal`), a temporary password
(`egauth.TemporaryPassword`), and the link or code of a delivery message. These are credentials.
The application delivers them to their recipient and keeps them out of logs and storage.

## What egauth guarantees

| Area | Guarantee | Held by |
|---|---|---|
| Configuration | every field validated at startup, all problems reported together; no request-time "misconfigured" | `egauth.New`, guards G4 and G5 |
| Routes | undeclared requests are 404; each route kind has a fixed gate set | `Auth.Routes`, G1, G19, G22 |
| Opt-outs | one struct, each with a reason, listed by `Auth.Posture` | `egauth.InsecureOptOuts`, G7 |
| Session state | minted once, sealed, replayed; renewal only strengthens | `principal.SessionAttrs`, G6, G8, G21 |
| Multi-factor | enrolled users never get a session without a second factor, whatever the modules | enrollment read from storage, G23 |
| Revocation | state-derived through a per-subject epoch, with fail-closed polling | stores, G21 |
| CSRF | unsafe and cross-site requests checked on fetch metadata, `Origin` and `Referer` | `internal/csrf`, G22 |
| Cookies | `__Host-` prefixed, `Secure`, `HttpOnly`; unauthenticated ceremonies bound to the browser | `internal/cookie`, G6 |
| Outbound requests | one SSRF-safe client, private networks refused | `internal/outbound`, G6 |
| Open redirect | one validator for every return target | `internal/redirect`, G22 |
| Enumeration | identical status, body and delivery count for known and unknown identifiers | G28 |
| Registration | no account exists until the email is verified | G23 |
| Federated identities | never linked to an existing account automatically | G23 |
| Passkeys | discoverable credentials and user verification required; clone warning suspends | G24 |
| Rate limiting | on by default, shared through storage, verified by a limiter probe at startup | `egauth.New`, G22 |
| Facades | authorization enforced inside `Accounts`, `Tenants` and `APIKeys` | G22 |

## What stays with the application

These are the responsibilities the library cannot take over:

- **Delivery.** Emails and texts are sent by the application's `egauth.EmailDeliverer` and
  `egauth.SMSDeliverer`. They carry working credentials, and delivery failures surface as events.
- **Key custody.** The KEK and signing seeds come from a secret store. Losing the KEK makes sealed
  data unreadable, and `egauth.New` refuses a key that cannot open existing data.
- **Claims.** The `egauth.ClaimsSource` decides roles and scopes. It is consulted at admission and
  on every renewal, and its answer is trusted.
- **Proxy truth.** `egauth.DirectClients` and `egauth.TrustedProxies` state which peers may set
  forwarding headers. A wrong statement changes which client address is rate limited.
- **Observability and idempotency.** Events go to the configured sink. Deliverers are idempotent on
  `DeliveryID`, which is stable across retries.
- **Backend atomicity.** A custom store must pass the shared contract suites, which assert the atomic
  behaviours (single-use consumption, rotation, lockout counters) the services rely on.

## Account-existence disclosure

Login, registration, password reset, magic link and code requests answer the same way for known and
unknown identifiers. `POST /register` always answers `202`: an address that already has an account
receives an account-exists notice instead of a link, and an account is created only when a link is
confirmed. Locked, disabled and unverified accounts answer exactly like a wrong password.

The enumeration guard (G28) covers every endpoint that takes an identifier. Any difference that
remains is behind authentication, where the caller already proves an account.

### Residual enumeration timing after raising Argon2id cost

The decoy path always uses the hasher's current cost, while verification of a not-yet-rehashed
account runs at the cost recorded in its stored hash. Right after an operator raises the cost, an
unknown account is slower than a registered one that has not logged in since. The gap closes for
each account at its next login and disappears once the population has refreshed. Treat enumeration
resistance as degraded until then, or rehash proactively. Rate limiting covers the remainder.

## Constant-time strategy and evidence

Secret-dependent comparisons (password verification, opaque-token equality, state, PKCE and nonce
binding, ceremony handles, one-time codes) rest on two arguments, neither a machine-checked proof:

1. **Structural.** Each comparison reaches a constant-time primitive without branching on its
   outcome: `crypto/subtle.ConstantTimeCompare` for passwords, codes and bindings, `hmac.Equal`
   for sealed handles. JWT verification pins the algorithm by key id and delegates signature
   comparison to the JWT library.
2. **Benchmarks.** `passwords/argon2` benchmarks compare correct and wrong passwords. They are
   evidence to inspect, not a CI gate, because a wall-clock threshold on a shared runner is too
   flaky to gate a build:

   ```sh
   go test -run=^$ -bench=BenchmarkCompare -benchmem ./passwords/argon2
   ```

A statistical timing analysis on dedicated hardware would strengthen the argument. An independent
review of the sealed-handle constructions and the protocol glue by someone other than the author
remains outstanding, so deployments with a higher assurance requirement should pin a reviewed commit
or commission their own review.

## Verifying a release

Release tags **from `v0.13.0` are signed with a dedicated SSH (ed25519) key**; keyless
Sigstore/[gitsign](https://github.com/sigstore/gitsign) and OpenPGP are supported alternatives.
SBOM release assets can be attested. Verify the tag before trusting a build.

**Tag signature (SSH — current).** `v0.13.0` and its `adapters/*/v0.13.0` tags are signed with
the maintainer signing key below (signing-only; it grants no repository access). Verification is
fully offline:

```sh
# The allowed_signers principal is the tag's tagger identity — derive it from the tag itself.
PRINCIPAL="$(git cat-file -p v0.13.0 | sed -n 's/^tagger .*<\(.*\)>.*/\1/p')"
echo "$PRINCIPAL ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB+o0uiapcumxvKKrbpTfvExxqeDSFzt8JGf3HdMYIZX egauth-release-signing" \
  >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

git verify-tag v0.13.0   # prints the verified identity and key fingerprint
```

**Tag signature (keyless Sigstore).** [gitsign](https://github.com/sigstore/gitsign) is the
supported model for releases that opt into keyless signing; when a release is keyless-signed,
verify the certificate identity too:

```sh
# Pinned: the verifier must be a version you have reviewed. Keep in sync with GITSIGN_VERSION in
# the Makefile.
go install github.com/sigstore/gitsign@v0.13.0   # or: brew install gitsign
git config --global gpg.x509.program gitsign
git config --global gpg.format x509

git verify-tag vX.Y.Z    # cryptographic integrity + Sigstore transparency-log inclusion
gitsign verify \
  --certificate-identity=<maintainer-identity> \
  --certificate-oidc-issuer=https://github.com/login/oauth \
  vX.Y.Z                 # also verifies *who* signed it
```

`git verify-tag` returns 0 for a cryptographically valid signature but does not check the
certificate claims; `gitsign verify` performs the full identity check against the
`--certificate-identity` recorded in the release notes. First-time keyless verification may
need network access to refresh the local Sigstore trust root; afterwards it works offline.

For **OpenPGP** or a different **SSH** key, import (or allow-list) the published public key and
run `git verify-tag vX.Y.Z`; see [RELEASING.md](RELEASING.md) Step 5 for setup.

**Release artifacts (SBOM).**

```sh
# GitHub artifact attestations (once the release workflow attests the artifacts):
gh attestation verify libauth-vX.Y.Z.sbom.json --repo JLugagne/egauth

# or a keyless cosign bundle attached to the release:
cosign verify-blob \
  --bundle libauth-vX.Y.Z.sbom.json.sigstore.json \
  --certificate-identity=<maintainer-identity> \
  --certificate-oidc-issuer=https://github.com/login/oauth \
  libauth-vX.Y.Z.sbom.json
```

Maintainers run the identical check before pushing a tag:
`bash scripts/verify-release-tag.sh <tag>` fails on a missing, lightweight or unsigned tag.

> **Historical gap.** Tags up to and including `v0.12.0` are **unsigned**: `v0.12.0` is a
> lightweight tag, the `adapters/*/v0.12.0` tags are annotated but unsigned, and earlier tags
> (including every `adapters/pgx` tag; `adapters/pgx/v0.6.1` is also lightweight) predate
> signing — `git verify-tag` fails on them. They cannot be signed retroactively; treat them as
> unverified. The first signed release is `v0.13.0` (SSH/ed25519; verification above).

## Reporting a vulnerability

Please use **GitHub Private Vulnerability Reporting** — do **not** open a public issue for
security matters.

1. Go to the repository's **Security** tab.
2. Click **"Report a vulnerability"**.
3. Fill in the advisory form and submit.

Direct link: <https://github.com/JLugagne/egauth/security/advisories/new>

> **Note:** GitHub Private Vulnerability Reporting must be enabled in the repository's
> Security settings for the button to appear; this is verified separately.

## Supported versions

Only the latest `0.x` minor release receives security fixes. Older minor series are
unsupported and may be retracted.

| Version | Supported          |
| ------- | ------------------ |
| >= 0.3  | yes                |
| 0.2.x   | no (unsupported)   |
| 0.1.x   | no (retracted)     |

## Acknowledgement window

Security reports are acknowledged on a **good-faith, best-effort** basis:

- **72 hours** — initial acknowledgement (confirm receipt and assign a tracking ID).
- **7 days** — preliminary assessment (severity, reproduction status, and an estimated
  fix timeline).
