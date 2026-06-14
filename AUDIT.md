# Audit status

egauth's security review to date is an AI-driven audit only; it has not had an independent third-party human security audit, and that risk is accepted for v1.0 — pin a reviewed commit, commission your own audit, or wait if that trade-off is unacceptable.

This file is the living ledger of egauth's security-review history. It records, honestly,
**what has been reviewed and how**, **what has not**, **the accepted trade-offs**, and the
**escape hatch** for users who are not comfortable with the current status. The canonical
audit-status sentence above is reused verbatim across the README, the root package godoc
(`doc.go`), `llms.txt`, `SECURITY.md`, and the v1.0.0 `CHANGELOG` entry, and its presence on
those surfaces is enforced by a build-failing test (`TestDisclosure*` in `disclosure_test.go`).

## What "AI-driven audit" means here

The security review behind v1.0 was performed with AI-assisted (LLM-driven) analysis plus the
author's own engineering review. There has been **no independent third-party human security
audit**. "AI-audited" is **not** a synonym for "audited" — do not read it as one.

### What was reviewed (and how)

- **Adversarial review pass** over the security-sensitive modules (`identity`, `tokens`/`jwt`,
  `sessions`, `passwords`/`argon2`, `mfa`, `otp`, `passkey`, `oauth`) looking for high/critical
  issues. The pass found no high/critical issue at the reviewed commit.
- **Threat model + guarantees** documented in `SECURITY.md`: hashing at rest, constant-time
  comparison and authentication paths (with benchmark evidence), enumeration resistance,
  refresh-token rotation with theft detection, alg-pinned JWTs (`iss`/`aud` checks),
  secure-by-default cookies, pre-auth body caps, OAuth/OIDC PKCE + state CSRF binding + SSRF
  guard, WebAuthn user-verification defaults.
- **Cross-backend conformance suites** exercising the in-memory and PostgreSQL (`pgx`) stores
  against the same contract.
- **Periodic re-review** of security-relevant changes (see the dated security-review notes in
  `.llms/` and the project's review memory).

### What was NOT reviewed

- **No independent third-party human security audit.** No external firm or individual has been
  commissioned to audit the code, the cryptographic constructions, or the protocol flows.
- **No formal verification** of the cryptographic or constant-time properties — the
  constant-time guarantees are structural-by-construction with benchmark *evidence*, not a proof.
- **No published penetration test** against a deployed reference application.
- **No third-party supply-chain / dependency audit** beyond automated tooling.

### Accepted trade-offs (for v1.0)

- v1.0 ships **without** an external human audit. **That risk is explicitly accepted** for the
  v1.0 release. An independent human audit is a strongly-encouraged **post-v1 follow-up**, not a
  v1.0 blocker. The v1.0 requirement is honest, prominent, build-enforced *disclosure* of this
  status — see the milestone PRD.

## Escape hatch — for the cautious user

If shipping on an AI-only-reviewed auth library is not acceptable for your use case, you have
clearly-labeled options, in increasing order of assurance:

1. **Pin a reviewed commit/tag** in your `go.mod` for reproducible builds, and review the delta
   yourself before bumping. egauth follows SemVer; pin an exact version rather than tracking a
   floating branch.
2. **Run your own review / commission an external audit** of the pinned commit. Issues, PRs, and
   security reports are genuinely welcome — see `SECURITY.md` for responsible disclosure.
3. **Wait** for an independent human audit to be recorded in the ledger below before adopting it
   for anything sensitive.

## Independent human audits

_None yet._

<!--
  When an independent human audit is completed, append an entry here. Suggested shape:

  ### <YYYY-MM-DD> — <auditor / firm>
  - Scope: <modules / commit range audited>
  - Commit reviewed: <git SHA / tag>
  - Report: <link>
  - Findings: <count by severity> — <status: open / fixed in vX.Y.Z>
-->

## Re-disclosure policy (post-v1)

Any post-v1 **security-relevant** change must re-disclose its review status: add a note to the
`CHANGELOG` entry (and, where applicable, a reviewed-delta note in `.llms/`) stating what
changed and whether it was re-reviewed. The canonical audit-status sentence stays in place until
an independent human audit is recorded above, at which point the surfaces and this ledger are
updated together.
