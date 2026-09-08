# Config & infra audit — 2026-09-08-1945 (commit 6f16690)

Scope: CI/CD workflows, Dockerfiles/IaC, debug endpoints, insecure defaults, Go build config.
Worktree audited: `.security-audit/2026-09-08-1945/wt-config-infra` (clean checkout of main).

## Checked (with verdict)

- **`.github/workflows/ci.yml`** — PASS. Top-level `permissions: contents: read`; no per-job
  permission escalations; no `pull_request_target`; triggers are `push`/`pull_request` on `main`
  only. All third-party actions SHA-pinned with version comments
  (checkout v7.0.1, setup-go v7.0.0, upload-artifact v7.0.1). No inline scripts exfiltrating
  secrets; the only credential is the ephemeral Postgres service password (`testuser`/`testpass`)
  scoped to the CI service container. govulncheck@v1.1.4 pinned and run for core + adapters/pgx.
- **`.github/workflows/pages.yml`** — PASS. Minimal `permissions` (`contents: read`,
  `pages: write`, `id-token: write` — the documented minimum for Pages). Trigger is
  `push: main` + `workflow_dispatch` only (no PR trigger, so no PR-abuse of the write tokens).
  Actions SHA-pinned (checkout, configure-pages v6.0.0, upload-pages-artifact v5.0.0,
  deploy-pages v5.0.1). Hugo installed via HTTPS download of a pinned version (0.162.1).
- **`.github/dependabot.yml`** — PRESENT (gomod + github-actions, weekly). Profile's "no
  Dependabot visible" is outdated; automated update PRs are configured.
- **Dockerfiles / IaC** — ABSENT, verified (`Dockerfile*`, `docker-compose*` do not exist; Go-only
  repo). Nothing to audit.
- **Debug endpoints** — NONE. No `net/http/pprof` or `expvar` import anywhere; no `/debug`,
  `/metrics`, version, or pprof routes. `health/` exports only the `Pinger` interface (no HTTP
  handler, no version/info leak). `webapp.NewWebApp` mounts exactly four routes
  (`/auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`, overridable via
  `Config.Routes`) on a fresh `http.ServeMux` — no debug surface. `examples/fullstack`
  exposes only auth/mfa/passkey/admin-demo/`/me` routes, no debug or metrics endpoints.
- **Insecure defaults** — SECURE BY DEFAULT. `WithInsecureNoOriginCheck` (identity/mfa/otp/tokens),
  `WithInsecureCookies` (identity/oauth/passkey/tokens), `WithInsecureURLs` /
  `WithInsecureDiscoveryURLs` (oauth), and `WithAllowUnverifiedEmail` (oauth) are all opt-in;
  defaults are: same-origin check ON, `Secure` cookies ON (`tokens.DefaultCookies`),
  unverified provider email REJECTED, PKCE ON. `webapp.Config` refuses to build without
  `TrustedOrigins` unless the caller explicitly opts out, and refuses `SigningKey == ""`.
  No default tenant (empty = single-tenant), no default keys in library code.
  `tokens/handlers.go` additionally has `warnIfInsecureMisuse` runtime warnings.
- **`go.mod` build config** — SANE, not a finding. `go 1.26.7`; `retract` block retracts only the
  pre-public-hardening tags v0.1.0–v0.2.1 with a documented rationale (superseded by v0.3.0).

## Ruled out (explicitly not findings)

- `examples/fullstack/main.go` uses `WithInsecureNoOriginCheck`, `passkey.WithInsecureCookies`,
  a placeholder `SecretKey` ("replace-with-...-in-production!") and a zero `cookieKey` — DEMO ONLY,
  each site carries a comment directing production to replace it. Not a shipped default; library
  consumers do not inherit it. (Copy-paste hardening note at most, not a vulnerability.)
- `WithAllowUnverifiedEmail`-type opt-outs exist but are OFF by default — per audit rules, only
  insecure DEFAULTS are flaggable.
- `coverage` job is declared non-gating by design — informational, not a vuln-scanning control.

## Per-finding summary

- **CFG-01 (medium confidence, CVSS 3.1 low): govulncheck does not cover the adapters/otel
  module.** `adapters/otel` is a separate Go module with real third-party deps
  (`go.opentelemetry.io/otel* v1.46.0`) and its own CI job (vet + test), but the `govulncheck`
  job scans only core and `adapters/pgx`. A known CVE in the OTel SDK tree would not fail CI.
  Fix: add a govulncheck step with `working-directory: adapters/otel` (or a per-module matrix).

## CI dependency-scanning status verdict

**PARTIAL PASS — one coverage gap (CFG-01).** govulncheck (pinned v1.1.4) runs on every push/PR
for the core and adapters/pgx modules; Dependabot covers gomod + GitHub Actions weekly; all
actions SHA-pinned with least-privilege tokens. Gap: adapters/otel is unscanned. No OSV/Trivy,
but for a Go-only repo govulncheck covers the Go vuln database adequately once the otel gap is
closed. Whether these jobs are GitHub *required status checks* (merge-gating) is a repo-settings
property not verifiable from a local checkout — recommend confirming `govulncheck` is marked
required in branch protection for `main`. No SCA re-scan performed per audit instructions.
