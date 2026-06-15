---
id: TASK-014
title: Bounded / self-evicting in-memory stores (sessions, otp, ratelimit)
description: Make the in-memory unbounded-growth footgun harder to hit. Ship a bounded variant or self-evict on a configurable cap by default for sessions/memory, otp/memory, and ratelimit.TokenBucket. Split off from TASK-005 (#23), whose CSRF + insecure-cookie [BLOCK] items are already done.
milestone: M1-v1.0
epic: secure-defaults
status: in_progress
priority: normal
type: feature
blocked_by: []
branch: "task/TASK-014-bounded-self-evicting-stores"
---

## Actions

- [x] Add a bounded/self-evicting variant for `sessions/memory` (configurable max-size cap with eviction) or document why the janitor-only model stays
- [x] Add a bounded/self-evicting variant for `otp/memory`
- [x] Add a bounded/self-evicting variant for `ratelimit.TokenBucket`
- [x] Keep the existing unbounded + janitor path available for callers who prefer it

## Definition of Done

- [x] A bounded store evicts at a configurable cap and never grows past it (verified by test) | run: go test ./sessions/... ./otp/... ./ratelimit/...
- [x] The cap/eviction policy is documented in each package's doc comment and in architecture.md
- [x] No breaking change to the existing constructors — the bounded variant is additive (verified by build) | run: go build ./...
- [x] All Actions checkboxes above are `[x]`

## Discussion

### 2026-06-14 — Implementation complete: ready for review

**sessions/memory**: `NewBoundedStore(maxSize int)` added to `store.go`. The `Store` struct gained a `maxSize int` field (0 = unbounded). `CreateSession` evicts via `evictOne()` helper when the cap is reached: expired sessions first, then the soonest-expiring live session. `Len()` exposes the current count. Package doc updated in `doc.go`.

**otp/memory**: `NewBoundedStore(maxSize int)` added. `SaveOTP` detects new vs. upsert keys and only evicts on genuine inserts. Eviction policy: expired codes first (by earliest ExpiresAt), then soonest-expiring live code. `Len()` added. Package doc updated in `doc.go`.

**ratelimit.TokenBucket**: `WithMaxKeys(n int) Option` added. `TokenBucket` struct gained `maxKeys int` (0 = unbounded). `Allow` calls `evictOne(now)` when a new key would exceed the cap — evicts the bucket with the most tokens (closest to full / least under pressure). `KeyCount() int` added for testing and monitoring. `TokenBucket` struct doc updated with a "Bounding memory growth" section listing both strategies.

**architecture.md** (`.llms/architecture.md`): "Storage backends" section updated with a table comparing all three bounded variants and their eviction policies.

**No breaking changes**: all existing `NewStore()` / `NewTokenBucket()` constructors are unchanged. The unbounded + janitor model remains fully supported.

**How to verify each DoD item:**
- Bounded cap never exceeded: `go test ./sessions/memory/... -run TestBoundedStore` and `go test ./otp/memory/... -run TestBoundedOTPStore` and `go test ./ratelimit/... -run TestTokenBucket_WithMaxKeys`
- Eviction policy docs: `go doc github.com/JLugagne/egauth/sessions/memory`, `go doc github.com/JLugagne/egauth/otp/memory`, `go doc github.com/JLugagne/egauth/ratelimit.TokenBucket`; also `.llms/architecture.md` "In-memory store growth control" table
- No breaking change: `go build ./...` passes cleanly
- Full suite: `go test ./sessions/... ./otp/... ./ratelimit/...` — 111 tests pass

### 2026-06-13 — Split off from TASK-005 (GitHub issue #23, v1 §3)
Source: https://github.com/JLugagne/egauth/issues/23 (the [WANT] bounded-stores bullet).
TASK-005's two [BLOCK] items (CSRF origin-check-by-default, insecure-cookie warning) are verified done in the SDK, so this leftover [WANT] is carved out here as its own task. Today all three stores are unbounded maps guarded by a single mutex; eviction is consumer-scheduled via `janitor`. This is a documented trade-off (architecture.md) — adopting a bounded default is the work. Also relates to the sharded-stores item in TASK-012 (#29) performance.
