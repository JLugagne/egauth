# Refresh-token family state machine

This document describes the refresh-rotation contract of the `egauth.JWT` backend, implemented over
the `tokens.Store` contract of `store/tokens`. It lists the states of a refresh token and its
family, the legal transitions between them, and the invariants every store implementation upholds.
The shared suite in `store/tokens/storetest` asserts them against the memory and pgx stores.

## Definitions

A **family** is the set of refresh records sharing one family id. A family is created by a login
and every successful rotation appends exactly one new member while consuming its parent, forming a
chain. Records are keyed by the SHA-256 digest of the token; the token itself is never stored. Each
record carries the sealed session attributes verbatim and the store never decodes them.

A **head** is the single token of a family that can still be rotated.

A **lineage** is the chain of families a login journey continues through: a reissue (password
change, factor enrollment, reauthentication) revokes a family and starts a new one in the same
lineage.

## Per-token states

| State | Representation | Rotatable |
|---|---|---|
| `live` | present, not consumed, family not revoked, inside idle and absolute lifetime | yes |
| `consumed` | a consumption time and consumer fingerprint are recorded | no |
| `revoked` | the family is revoked | no |
| `expired` | past the idle expiry or the absolute family expiry | no |
| `absent` | not returned by the store (unknown, wrong tenant, erased or reaped) | no |

`consumed` and `revoked` are persistent markers: the record is retained after consumption so that a
replay can be detected.

## Family states

| State | Definition |
|---|---|
| `active` | exactly one member is `live` (the head) |
| `revoked` | the family is revoked and appended to the revocation feed |
| `exhausted` | no member is `live` and the family is not revoked |

## Transitions

| Event | Precondition | Effect | Result |
|---|---|---|---|
| create | none | new `live` head, new family | the first token |
| rotate (live head) | head `live` | head consumed, new `live` head in the same family, atomically | the next token |
| rotate (expired or unknown) | idle-expired, wrong tenant, erased | none | `store.ErrNotFound` |
| rotate (revoked family) | family revoked or past its absolute expiry | none | `tokens.ErrRevoked` |
| replay of a consumed token, inside the grace window, same non-empty fingerprint | consumed less than `tokens.ReuseGrace` ago by the presenting client | none | `tokens.ErrConcurrent` |
| replay of a consumed token, inside the grace window, other fingerprint | consumed less than `tokens.ReuseGrace` ago by another client | family revoked | `tokens.ErrReused` |
| replay of a consumed token, after the grace window | consumed longer ago than the window | family revoked | `tokens.ErrReused` |
| concurrent rotation of one head | two requests present the same head | exactly one consumes it | winner a new token, loser `tokens.ErrConcurrent` |
| reissue | the family is live and the new record continues its tenant, subject and lineage | family revoked, new family inserted, atomically | `nil` or `store.ErrConflict` |

The grace window is measured with the store's clock against the persisted consumption time, never
with an application clock.

## Invariants

* **I1: single head.** A family never has two simultaneously usable tokens. Consumption and
  insertion of the successor are one atomic step, and a failed rotation leaves liveness unchanged.
* **I2: replay is theft outside grace.** Replaying a consumed token outside the benign race, or
  from another client, revokes the entire family and appends it to the feed, so no descendant
  remains usable.
* **I3: continuity.** A successor must continue the consumed token's tenant, subject, lineage and
  family, otherwise the store returns `store.ErrConflict` and changes nothing. A tenant is
  immutable across rotations.
* **I4: sealed attributes are replayed.** The successor carries the sealed attributes of the
  parent. Rotation never adds a factor or advances the authentication time.
* **I5: single winner under concurrency.** Concurrent rotation of one head yields exactly one
  successor; the losers observe benign concurrency, not theft.
* **I6: reissue is atomic against revocation.** A reissue racing `RevokeForSubject` leaves no
  surviving family.
* **I7: the feed is monotonic.** `RevocationsSince` returns every revocation appended after a
  cursor, including one stamped with an earlier timestamp.

## Verification

`store/tokens/storetest` asserts these invariants, including 32-goroutine rotation and reissue
races, against both backends. `internal/session/backendtest` asserts the observable behaviour
through the session backend: reuse revokes the family, a revoked session is refused within the
poll bound, and the absolute lifetime is enforced.
