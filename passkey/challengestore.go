package passkey

import (
	"context"
	"time"
)

// ChallengeStore provides single-use, TTL-bounded storage of in-flight ceremony challenges
// so a captured Finish request cannot be replayed (SEC-05). It is REQUIRED by default: wire it
// via Config.ChallengeStore (NewService fails with ErrChallengeStoreMissing otherwise) or
// override it per handler with WithChallengeStore. A caller who knowingly accepts cookie-only
// protection — the ceremony cookie is then the only single-use mechanism, which a captured raw
// request can bypass — must opt out explicitly via Config.InsecureNoChallengeStore.
//
// Implementations MUST make Consume atomic and single-use: the second Consume of the same
// (tenantID, challenge) returns (false, nil) even under concurrent callers. The challenge is
// a high-entropy, globally unique value, so keying on it is the security-critical part;
// tenant scoping is defense in depth.
type ChallengeStore interface {
	// Put records an issued challenge with an absolute expiry. Implementations should key on
	// (tenantID, challenge) and may prune expired entries lazily.
	Put(ctx context.Context, tenantID, challenge string, expiresAt time.Time) error
	// Consume atomically removes the challenge and reports whether it was present and
	// unexpired. A second Consume of the same challenge MUST return (false, nil).
	Consume(ctx context.Context, tenantID, challenge string) (bool, error)
}
