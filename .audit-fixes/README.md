# libauth completeness — fix checklists (TEMPORARY)

Working checklists derived from the 2026-05-29 real-code completeness audit
(17-agent workflow, verified against source + OWASP ASVS / NIST 800-63B).

Tick items as they are completed + tested. Delete `.audit-fixes/` once the work fully lands.

## ⟳ Resume in a new session (READ THIS FIRST)
- **Branch:** `fix/audit-completeness` (off `main`). All work + these checklists are committed
  here as per-item commits — `git log --oneline main..HEAD` is the progress ledger.
- **Where things stand:** see Progress at the bottom of this file. 9/34 done (C1-C3, I1-I4,
  I17, I18-jwt). Next up: **I5** (change-email) then **I6** (account-deletion) — quick identity
  wins — then the order in "Suggested order" below.
- **Findings/context:** `AUDIT-FINDINGS.md` (verdict + what's already solid, so you don't
  "re-fix" working code). Per-item detail in `01/02/03-*.md`. Feature request:
  `feature-per-tenant-oidc.md` (also saved as a Claude memory).
- **Conventions to keep:**
  - English-only code/comments. Conventional-commit messages, **no Co-Authored-By line**.
  - Commit **per item**; one item = test(s) + impl + green build, then commit.
  - Bug/vuln items: write the failing test FIRST to confirm, then fix. Feature items: behavior
    test first too.
  - Editing `.go`: prefer go-surgeon. **Gotcha hit this session:** `go-surgeon update` with the
    default `object:auto` can do a `replace_file` and clobber the whole file when given a single
    func — pass `object:"func"`, or use Edit/Write for surgical changes, and always
    `build_check` after.
- **Verify loop:** `go-surgeon build_check ./... (tests=true)` + `go vet ./...` + run the
  touched package's tests. pgx/testcontainers tests need Docker; memory-backed tests always run.
  Run `go`/`git` with the sandbox disabled (this env's bwrap loopback fails sandboxed).
- **Reproduce the audit:** workflow script at `.audit-fixes/audit-workflow.js`
  (re-run via the Workflow tool with `scriptPath`).

## Method (per global dev standards)
- Bug/vulnerability items: write a failing test that **confirms** the issue first,
  fix only once confirmed, keep the test as the regression guard.
- Feature items: write the behavior test first (TDD), then implement.
- After every item: `go build ./...` + `go vet ./...` + the affected package tests
  stay green. (pgx/testcontainers tests need Docker; memory-backed tests always run.)

## Severity files
- [01-critical.md](01-critical.md) — 4 items; block "safe-by-default + complete"
- [02-important.md](02-important.md) — 19 items; expected by serious adopters
- [03-nice-to-have.md](03-nice-to-have.md) — 11 items; polish / maturity

## Feature backlog (beyond the audit)
- [feature-per-tenant-oidc.md](feature-per-tenant-oidc.md) — per-tenant OIDC/OAuth provider
  assignment in multi-tenant deployments (bring-your-own-SSO). Builds on I9; do I9 first.

## Suggested order
1. C1 DoS cap → C2 rate-limit seam → I2 CSRF on token endpoints  (close abuse holes)
2. C3 change-password, I5 change-email, I6 account-deletion, I4 email normalization, I3 enum-oracle  (identity self-service + correctness)
3. I7 HIBP, I8 mailer, I1 otp handlers  (make it work out of the box)
4. I9 OIDC, I10 JWT key rotation, I11 audit hooks, I12 session refresh, I16 cleanup, I17 redaction, I18 config validation, I19 tenant consistency
5. Passkey (I13/I14), step-up (I15)
6. C4 docs (after API settles), then nice-to-haves

## Progress (branch fix/audit-completeness, per-item commits)
- Critical:      3 / 4   (DONE: C1 DoS, C2 rate-limit, C3 change-password; C4 docs deferred to last)
- Important:    18 / 19  (DONE: I1-I18; only I19 tenant-consistency remains)
- Nice-to-have:  0 / 11
- **Total:      21 / 34**   — whole module builds + `go vet` clean; all tests green incl. pgx via testcontainers

### Remaining important (1): I19 tenant enforcement consistency across backends (+ the
### UpdateUserEmail empty-tenant follow-up). NOTE: I19 involves a genuine design fork —
### "empty tenant = valid default single-tenant partition" vs "tenant required everywhere
### (ErrTenantRequired)". The codebase today overwhelmingly treats "" as the default partition;
### only otp-pgx SaveOTP and identity-pgx UpdateUserEmail are ErrTenantRequired outliers that
### disagree with their memory backends. Resolution should pick a posture, make it uniform
### across all stores+backends, document it, and add empty-tenant (useMultiTenant=false) contract
### coverage. Surface this fork before implementing.
### Then all nice-to-haves (N1-N11), C4 docs, and feature-per-tenant-oidc.md.
### Resume: read this file + the per-item git log on the branch (git log --oneline main..HEAD).
