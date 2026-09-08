# Security audit — summary (run 2026-09-08-1945)

Go auth library (`egauth`: JWT/sessions, Argon2id passwords, MFA/OTP, passkeys, OAuth/OIDC, keystore, Postgres adapters) — audited at commit `6f16690` via 6 worktree-isolated subagent audits plus chain analysis, each finding proven by an executed PoC test.

Counts: **8 findings — High 1, Medium 3, Low 4; confidence confirmed 6, likely 2, theoretical 0** (10 raw, 2 pairs merged as same root cause).

What matters most (see `full-report.md` for detail):
- **SECRETS-01 (High, 7.4):** example + docs publish valid-length JWT signing keys — copy-paste deployments mint forgeable tokens.
- **ENUM-01 (Medium, 5.3):** default login answers 429 for locked/disabled vs 401 for unknown — unauthenticated account enumeration, shipped in the default preset.
- **AS-02 (Medium, 4.3):** MFA step-up drops `MustChangePassword` on default wiring — forced-password-change bypass until next interactive login.
- **SECRETS-02 (Medium, 5.9):** example + docs publish usable passkey ceremony-cookie HMAC keys (one is 32 zero bytes).

Attack chains: **4 identified, none raising severity** — enumeration feeding must-change evasion, disabled-oracle corroboration via reset issuance, unsigned-OAuth-state + Host-derived redirect login-CSRF, and the copy-paste demo bundle (all detailed in `full-report.md` / `attack-chains.md`).

CI dependency scanning: **partial pass** — govulncheck pinned and gating for core + `adapters/pgx`, but the `adapters/otel` module is unscanned (filed as CFG-01, Low).
