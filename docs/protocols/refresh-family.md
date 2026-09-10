# Refresh-token family state machine

This document describes the refresh-token rotation contract implemented by `tokens/jwt`
(`Service.Rotate`, `Service.mintPair`) over the `tokens.Store` interface, using
`tokens/memory` as the reference store. It lists the states of a refresh token and its family,
the legal transitions between them, and the invariants the implementation must uphold. The
property tests in `tokens/jwt/rotation_property_test.go` drive this machine with deterministic
randomised operation sequences and check the invariants after every step.

## Definitions

A **family** is the set of refresh-token records sharing one `FamilyID`. A family is created by
`IssueTokenPair` (a fresh login) and every successful rotation appends exactly one new member
while consuming its parent, forming a chain. Only the SHA-256 hash of each token is stored.

A **head** is the single token of a family that can still be rotated.

## Per-token states

| State      | Representation                                                       | Rotatable |
| ---------- | -------------------------------------------------------------------- | --------- |
| `live`     | present, `ConsumedAt == nil`, `RevokedAt == nil`, `now <= ExpiresAt` | yes       |
| `consumed` | `ConsumedAt != nil` (single-use marker)                              | no        |
| `revoked`  | family revocation stamped the record's `RevokedAt`                   | no        |
| `expired`  | `now > ExpiresAt`                                                    | no        |
| `absent`   | not returned by the store (unknown, wrong tenant, or reaped)         | no        |

`expired` is evaluated against the service clock at use time. `consumed` and `revoked` are
persistent markers; the record is retained after consumption so a replay can be detected.

## Family states

| State            | Definition                                                                                              |
| ---------------- | ------------------------------------------------------------------------------------------------------- |
| `active`         | exactly one member is `live` (the head)                                                                 |
| `revoked`        | every member is `revoked`; lookups report `ErrTokenFamilyRevoked`                                       |
| `exhausted`      | no member is `live` and the family is not revoked (e.g. the head expired and was never replayed)        |

## Transitions

| Event                                   | Precondition                                                        | Effect                                                           | Result                                 |
| --------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------- |
| issue                                   | —                                                                   | new `live` head, new `FamilyID`                                  | `TokenPair`                            |
| rotate(live head)                       | head `live`; `now < AuthTime + MaxRefreshLifetime` (when configured) | head → `consumed`; new `live` head in the **same** family        | `TokenPair`                            |
| rotate(expired head)                    | head `expired`, or past `MaxRefreshLifetime`                        | none                                                             | `ErrTokenExpired`                      |
| rotate(unknown / wrong tenant)          | token not found in the tenant partition                             | none                                                             | `ErrRefreshTokenNotFound`              |
| replay(consumed), in grace, same client | consumed within `ReuseGracePeriod`; presenting client matches or is unknown | none (benign concurrency)                                 | `ErrRefreshConcurrent` (wraps `ErrRefreshTokenReused`) |
| replay(consumed), in grace, other client| consumed within `ReuseGracePeriod`; presenting client differs       | whole family → `revoked`                                         | `ErrRefreshTokenReused`                |
| replay(consumed), after grace           | consumed longer ago than `ReuseGracePeriod`, or strict mode         | whole family → `revoked`                                         | `ErrRefreshTokenReused`                |
| concurrent rotate of one live token     | two requests present the same head                                  | exactly one wins and consumes it; the family is not revoked       | winner `TokenPair`, losers `ErrRefreshConcurrent` |
| rotate in a revoked family              | family `revoked`                                                    | none                                                             | `ErrTokenFamilyRevoked` (wraps not-found) |

`ReuseGracePeriod` defaults to 10 seconds; a negative value selects strict mode, where any
replay of a consumed token is theft. The grace window is a wall-clock window measured from the
moment the store stamped `ConsumedAt`; the expiry and absolute-lifetime checks use the service
clock.

## Invariants

* **I1 — single head.** A family never has two simultaneously usable tokens. A successful
  rotation consumes the parent before (or atomically with) persisting the successor, and a
  failed rotation leaves liveness unchanged.
* **I2 — replay is theft outside grace.** Replaying a consumed token after the grace window, or
  at any time in strict mode, revokes the entire family, so no descendant remains usable. A
  revocation failure is surfaced, never silently swallowed.
* **I3 — tenant immutability.** Every descendant is persisted under the tenant of the family
  that was found and revoked, regardless of the tenant the claims provider returns. Cross-tenant
  lookups fail closed with `ErrRefreshTokenNotFound`.
* **I4 — `auth_time` preservation.** Every descendant records the family's original `AuthTime`;
  refresh never advances it, and a legacy zero `auth_time` stays zero.
* **I5 — forced-change flag monotonicity.** A descendant's `MustChangePassword` is the logical OR
  of the parent's flag and the claims provider's current value. It can be set on refresh but
  never cleared within a family.
* **I6 — issuer-controlled access lifetime.** A provider-supplied `ExpiresAt` is ignored on
  rotation; the access TTL is always the issuer's.
* **I7 — single winner under concurrency.** Concurrent rotation of the same head yields exactly
  one successor; the losers observe benign concurrency, not theft.

## Verification

`tokens/jwt/rotation_property_test.go` checks I1–I7 over deterministic seeded operation
sequences (`TestRotationProperty_FamilyInvariants`) and the concurrent-grace branch
(`TestRotationProperty_ConcurrentGraceSingleSuccessor`). The state-machine transitions
themselves are additionally covered by the focused unit tests in `tokens/jwt/rotation_test.go`.
