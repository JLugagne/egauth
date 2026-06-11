---
id: TASK-064
title: "Discoverable (usernameless) login has no challenge-store replay protection and ships no handler that wires it"
description: "The package's SEC-05 replay defence (record the challenge on Begin, atomically Consume it on Finish) is implemented ONLY in the username-based handlers (FinishLoginHandler/FinishRegistrationHandler via cfg.consumeChallenge). The discoverable login path is exposed solely as the Service method FinishD…"
milestone: M4-severity-medium
epic: passkey
status: done
priority: normal
type: bugfix
blocked_by: []
branch: main
---

## Actions

- [x] Write a failing regression test in `passkey` reproducing the flaw: The package's SEC-05 replay defence (record the challenge on Begin, atomically Consume it on Finish) is implemented ONLY in the username-based handlers (FinishLoginHandler/FinishRe…
- [x] Confirm the test FAILS against current code (proves the flaw exists)
- [x] Apply the fix: Ship BeginDiscoverableLoginHandler/FinishDiscoverableLoginHandler that record and consume the challenge (and apply the maxBodyBytes cap) exactly like the username handlers, OR have the Service-level BeginDiscoverableLogin/FinishDiscoverableLogin record/consume via s.challenges directly. At minimum,…
- [x] Re-run the test and the package suite; confirm green and no regressions

## Definition of Done

- [x] Regression test reproducing the finding fails before the fix and passes after (repo TDD rule) | run: go test ./passkey/...
- [x] The audit attack scenario no longer succeeds: The package's SEC-05 replay defence (record the challenge on Begin, atomically Consume it on Finish) is implemented ONLY in the username-based handlers (FinishL…
- [x] Build & vet clean | run: go vet ./... && go build ./...
- [x] If the fix changes documented behaviour, `SECURITY.md` / package docs updated to match
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-11 — From the 2026-06 multi-agent security audit ([MEDIUM])
**Location:** `passkey/service.go:257`  •  **Category:** replay  •  **Verifier consensus:** medium (1/1 confirmed real)

**What's wrong & impact**
The package's SEC-05 replay defence (record the challenge on Begin, atomically Consume it on Finish) is implemented ONLY in the username-based handlers (FinishLoginHandler/FinishRegistrationHandler via cfg.consumeChallenge). The discoverable login path is exposed solely as the Service method FinishDiscoverableLogin, which never references s.challenges and never consumes the challenge, and BeginDiscoverableLogin never Puts one. There are also NO BeginDiscoverableLoginHandler / FinishDiscoverableLoginHandler shipped and no exported helper to record/consume the challenge, so a consumer who adopts usernameless passkeys (an increasingly default UX) has no way to obtain the replay protection the rest of the package and SECURITY.md promise ('the challenge is recorded on Begin and atomically consumed on Finish, so a captured raw Finish request cannot be replayed within the cookie TTL'). I confirmed empirically: with a ChallengeStore wired, an identical sign-count-0 discoverable assertion submitted twice to FinishDiscoverableLogin BOTH verify successfully. Because most platform authenticators (e.g. iCloud Keychain) report a signature counter of 0, the clone-counter tripwire never fires, so a captured raw Finish request can be replayed within the cookie TTL to re-authenticate as the victim. Attack precondition: capturing one raw Finish request (e.g. a request-body log sink, a malicious reverse proxy, or a compromised client) — exactly the threat the package treats as serious enough to make a ChallengeStore required-by-default for the username flow.

**Evidence**
```go
func (s *Service) FinishDiscoverableLogin(ctx context.Context, tenantID string, session webauthn.SessionData, r *http.Request) (*Credential, uuid.UUID, error) {
	...
	cred, err := s.wa.FinishDiscoverableLogin(handler, session, r)  // no s.challenges.Consume anywhere
  // and no BeginDiscoverableLoginHandler/FinishDiscoverableLoginHandler exist in handlers.go
```

**Recommended fix**
Ship BeginDiscoverableLoginHandler/FinishDiscoverableLoginHandler that record and consume the challenge (and apply the maxBodyBytes cap) exactly like the username handlers, OR have the Service-level BeginDiscoverableLogin/FinishDiscoverableLogin record/consume via s.challenges directly. At minimum, export a record/consume helper and prominently document that consumers wiring their own discoverable handlers MUST consume the challenge, otherwise replay protection is absent for that flow. Until then, SECURITY.md should explicitly carve out that discoverable login is not replay-protected by the ChallengeStore.

### 2026-06-11 — Closed by close-auditor: all Actions and DoD verified
