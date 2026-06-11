---
id: TASK-072
title: "Recovery-email independence check is byte-exact, so a Unicode/IDN variant of the primary address passes the ErrRecoveryEmailIsPrimary guard"
description: "RequestRecoveryEmail enforces that a recovery email must be INDEPENDENT of the primary login address via a byte-exact comparison recoveryEmail == user.Email (both run through the same normalizeEmail, which does no Unicode/IDN folding). Because an NFD-form localpart or a punycode-vs-Unicode domain of…"
milestone: M5-severity-low
epic: identity
status: done
priority: low
type: bugfix
blocked_by: []
branch: "main"
---

## Actions

- [x] Write a failing regression test in `identity` reproducing the flaw: RequestRecoveryEmail enforces that a recovery email must be INDEPENDENT of the primary login address via a byte-exact comparison recoveryEmail == user.Email (both run through the s…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Compare the recovery address against the primary using the same fully-canonicalized form proposed in the related finding (NFC + IDN A-label), so a Unicode/IDN-equivalent of the primary is correctly rejected as ErrRecoveryEmailIsPrimary.
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./identity/...
- [x] The audit attack scenario no longer succeeds: RequestRecoveryEmail enforces that a recovery email must be INDEPENDENT of the primary login address via a byte-exact comparison recoveryEmail == user.Email (bo…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match (no change needed: fix strengthens enforcement to match the already-documented "recovery email may not equal the primary" property)
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([LOW])
**Location:** `identity/service.go:994`  •  **Category:** weak-binding  •  **Verifier consensus:** low (1/1 confirmed real)

**What's wrong & impact**
RequestRecoveryEmail enforces that a recovery email must be INDEPENDENT of the primary login address via a byte-exact comparison recoveryEmail == user.Email (both run through the same normalizeEmail, which does no Unicode/IDN folding). Because an NFD-form localpart or a punycode-vs-Unicode domain of the primary address normalizes to a DIFFERENT string (proven in the related finding), an attacker who has compromised the primary mailbox (or a user who simply enrolls a confusable variant) can register a 'recovery email' that is a Unicode/IDN variant of the primary and slip past the ErrRecoveryEmailIsPrimary check. If that variant resolves to the same physical mailbox at the provider, the supposedly INDEPENDENT recovery channel is the same inbox — defeating the documented 'breaking the single-email takeover chain' / 'a recovery email may not equal the primary address' property (SECURITY.md:101-104). Impact is bounded because the recovery email is 'a contact attribute, not a login key' (it cannot be authenticated against and never re-keys an identity), so this weakens the freshness/step-up independence gate rather than granting direct account takeover.

**Evidence**
```go
if recoveryEmail == user.Email {
		return "", ErrRecoveryEmailIsPrimary
	}  // service.go:994-996 — byte-exact; an NFD or punycode variant of user.Email is not equal and is accepted as 'independent'.
```

**Recommended fix**
Compare the recovery address against the primary using the same fully-canonicalized form proposed in the related finding (NFC + IDN A-label), so a Unicode/IDN-equivalent of the primary is correctly rejected as ErrRecoveryEmailIsPrimary.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
