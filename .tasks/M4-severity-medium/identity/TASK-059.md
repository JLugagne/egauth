---
id: TASK-059
title: "normalizeEmail does no Unicode (NFC/NFKC) or IDN/punycode canonicalization, weakening the cross-flow email identity key and the OAuth takeover-by-email guard"
description: "normalizeEmail is the single cross-flow identity key: its output is the byte-exact uniqueness key for password accounts (CreateUser -> UNIQUE INDEX idx_users_email_tenant ON users(tenant_id, email), migrations/001_create_tables.sql:11; FindUserByEmail -> WHERE email = $1, adapters/pgx/identity/store…"
milestone: M4-severity-medium
epic: identity
status: done
priority: normal
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `identity` reproducing the flaw: normalizeEmail is the single cross-flow identity key: its output is the byte-exact uniqueness key for password accounts (CreateUser -> UNIQUE INDEX idx_users_email_tenant ON users(…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Canonicalize before keying: NFC- (or NFKC-) normalize the address with golang.org/x/text/unicode/norm, and convert the domain to its A-label with golang.org/x/net/idna.Lookup.ToASCII (or consistently to the U-label) so punycode and Unicode domains map to one key; consider lowercasing the domain sepa…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/...
- [x] The audit attack scenario no longer succeeds: normalizeEmail is the single cross-flow identity key: its output is the byte-exact uniqueness key for password accounts (CreateUser -> UNIQUE INDEX idx_users_em…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `identity/service.go:21`  •  **Category:** tenant-isolation  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
normalizeEmail is the single cross-flow identity key: its output is the byte-exact uniqueness key for password accounts (CreateUser -> UNIQUE INDEX idx_users_email_tenant ON users(tenant_id, email), migrations/001_create_tables.sql:11; FindUserByEmail -> WHERE email = $1, adapters/pgx/identity/store.go:111), the password-login lookup (service.go:398/408), AND the input to the OAuth account-takeover guard in LinkOrCreateIdentity (service.go:783-808). The function only trims and ToLowers; it performs no Unicode normalization and no IDN A-label/U-label folding. I verified empirically that the same human/IdP-identical address maps to DIFFERENT keys: NFC "josé@example.com" (precomposed U+00E9) vs NFD ("e"+U+0301) -> distinct strings (NFC==NFD => false); and the U-label domain "user@münchen.de" vs its A-label "user@xn--mnchen-3ya.de" -> distinct strings. Impact: the takeover-by-email guard at service.go:804 (FindUserByEmail on the OAuth-supplied email) is byte-exact, so an external identity whose verified email differs from a pre-existing password account ONLY in Unicode form (NFC vs NFD localpart) or domain encoding (Unicode vs punycode) is NOT detected as a shared-email collision; LinkOrCreateIdentity then silently JIT-provisions a SECOND, distinct account for what every other system (mail provider, IdP, the user) treats as one address. This breaks the SECURITY.md guarantee that the callback 'never auto-link[s] an external identity onto a pre-existing account that merely shares the email' (SECURITY.md:43) and the doc-comment claim that normalizeEmail 'returns its canonical form' closing the 'duplicate-account hazard' (service.go:15-18) — the canonicalization is only delivered for ASCII case, not for Unicode-equivalent or IDN-equivalent forms. SECURITY.md does not document any accepted Unicode/IDN limitation, so this is an undelivered guarantee, not an accepted trade-off. (Note: the inverse over-match direction — distinct addresses folding to the same key, e.g. Kelvin sign U+212A 'K' lowercasing to ASCII 'k' so "userK@x.com" and "userk@x.com" both yield "userk@x.com", verified collide==true — is fail-safe for the OAuth path because the guard then fires and returns ErrEmailAlreadyExists, but it causes registration denial / griefing at the unique index.)

**Evidence**
```go
func normalizeEmail(email string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil {
		return "", ErrInvalidEmail
	}
	return strings.ToLower(addr.Address), nil
}  // service.go:21-27 — no NFC/NFKC, no IDN folding. Verified: NFC josé != NFD josé; münchen.de != xn--mnchen-3ya.de. Guard at service.go:804: if _, ferr := s.store.FindUserByEmail(ctx, tenantID, email); ferr == nil { return nil, ErrEmailAlreadyExists }
```

**Recommended fix**
Canonicalize before keying: NFC- (or NFKC-) normalize the address with golang.org/x/text/unicode/norm, and convert the domain to its A-label with golang.org/x/net/idna.Lookup.ToASCII (or consistently to the U-label) so punycode and Unicode domains map to one key; consider lowercasing the domain separately and applying NFC to the localpart. Apply the SAME canonicalization in every call site (password Register/Authenticate AND OAuth LinkOrCreateIdentity) since they share normalizeEmail. If full canonicalization is intentionally out of scope, document the exact accepted limitation in SECURITY.md and soften the service.go:15-18 'canonical form' comment, and reject (rather than silently pass) localparts/domains carrying combining marks or non-ASCII confusables.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
