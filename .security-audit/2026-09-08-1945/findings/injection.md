# Injection audit — findings notes

Auditor: injection specialist. Commit `6f16690`. Worktree:
`.security-audit/2026-09-08-1945/wt-injection`.

## Verdict

**0 findings (0 confirmed, 0 likely, 0 theoretical).** Every in-scope
candidate was traced from untrusted source to sink and proven safe by a
passing PoC/robustness test (tests assert the *attack fails*). An empty
`injection.json` (`[]`) is the honest output — no pattern without
plausible attacker-controlled input was elevated to a finding.

## What was checked (source → sink traces)

- **SQL (all 8 pgx stores: identity, keystore, mfa, oauth, otp, passkey,
  sessions, tokens):** every query is a static string with `$n` bind args;
  zero `Sprintf`/concat/ORDER-BY/LIMIT building in non-test code. Tenant IDs
  (host-resolver/host-header-influenced), emails, hashes all travel as args.
- **Migration runner (`pgxmigrate.Run`):** single interpolation point —
  the version filename into a SQL literal — with `'`-doubling. Source is the
  deploy-time embedded FS, not remote input.
- **Command/shell:** only `internal/doctest` (`exec.Command("go","doc",…)`,
  no shell, AST-identifier args, maintainer-run dev tool).
- **Path traversal/ZipSlip:** only doctest (`filepath.Join(root,…)` with a
  CLI flag) and `fs.ReadFile(fsys, "migrations/"+name)` over embedded FS
  (ReadDir base names cannot contain `/`).
- **JWT parse (`tokens/jwt`):** kid-first signer resolution + strict
  `token.Method.Alg()` pinning; `none`/wrong-key/unknown-kid rejected.
- **Argon2 PHC parse:** `time<1`/`threads<1`/`keyLen==0`/sub-floor-memory
  rejected pre-KDF (would panic `deriveKey`); `memory > MaxMemoryKiB`
  (512 MiB) rejected pre-allocation; opaque `ErrInvalidPassword` throughout.
- **OAuth state cookie:** `.`-joined fields with base64url alphabet (cannot
  contain the separator); HMAC-SHA256 over the payload in signed mode;
  tamper/swap/truncate/extend all fail closed. Unsigned legacy mode is
  self-flow only (forged tenant still must equal the host resolver value).
- **Passkey:** 64 KiB `MaxBytesReader` caps before WebAuthn/CBOR decode;
  challenge cookie is HMAC-sealed (`seal`/`open` with length check).
- **JWKS (`publicJWKFromKey`):** `x509` parse errors returned, never panic;
  input is KEK-opened operator key material, not remote input.
- **LDAP/XPath/EL/template:** no occurrences (`text/template`,
  `html/template`, `ldap`, `xpath` — zero hits).
- **Header/CRLF:** all `Header().Set` values static; cookie values are
  server-minted or base64url; `AuthCodeURL` uses `url.Values.Encode`;
  Host-derived `redirect_uri` is query-escaped (CRLF cannot survive Go's
  request parser into `r.Host`).

## Ruled-out items (appendix)

R1 pgxmigrate version-literal interpolation — escaped + trusted source
(proof: `TestPocMigrateFilenameNoBreakout`). R2 Unsigned legacy OAuth state
forgeability — self-flow, bound downstream (proof: tamper tests). R3
`doctest` exec/file calls — dev-only, no shell. R4 Host-derived tenant/URL
reflection — parameterized / URL-encoded. R5 `pub.Bytes()` slicing in JWKS —
operator key material, errors handled.

## PoC test files (all passing, kept in worktree)

- `wt-injection/oauth/poc_injection_test.go` — separator/CRLF injection +
  signed-cookie tamper suite (PASS)
- `wt-injection/passwords/argon2/poc_injection_test.go` — 16 hostile PHC
  strings: no panic, no OOM, fast opaque reject (PASS)
- `wt-injection/tokens/jwt/poc_injection_test.go` — alg=none, wrong-key,
  unknown/numeric/empty kid, truncated, 10 MB blob (PASS)
- `wt-injection/adapters/pgx/internal/pgxmigrate/poc_injection_test.go` —
  hostile filename breakout-proof (PASS)
- `wt-injection/adapters/pgx/tokens/poc_injection_test.go` — classic `' OR
  '1'='1` payloads stay in bind args (PASS)

Existing suites re-run green: `oauth`, `tokens/jwt`, `passwords/argon2`
(`-short`).

## Environment note (pre-existing, not a finding)

`adapters/pgx` requires `egauth v0.10.0`, unresolvable offline (unknown
revision, main tree included), so pgx PoC tests were run with a temp
modfile (`/tmp/pgx_poc.mod`) adding `replace egauth => ../..`. Worktree
contains only the 5 PoC files; no other modifications.
