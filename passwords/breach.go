package passwords

import "context"

// BreachChecker reports whether a candidate password appears in a corpus of known-compromised
// credentials (a "have I been pwned"-style check). It is a HOOK: libauth ships no
// implementation and makes no network calls of its own — the consumer wires one in.
//
// The canonical, privacy-preserving implementation is the k-anonymity range query (e.g.
// HaveIBeenPwned): SHA-1 the password, send only the first 5 hex characters of the digest to
// the service, and check whether the returned suffix list contains the rest — the full
// password (and full hash) never leave the process. An offline bloom filter or a local
// blocklist works too.
//
// Implementations receive the plaintext password and MUST treat it as a credential (never log
// or persist it). They should respect ctx cancellation/deadlines.
type BreachChecker interface {
	// IsBreached reports whether the password is known to be compromised. A non-nil error
	// (e.g. the backing service is unreachable) is propagated by the policy unchanged, so the
	// caller chooses the fail-open vs fail-closed posture by how it handles that error.
	IsBreached(ctx context.Context, password string) (bool, error)
}

// BreachCheckerFunc adapts a plain function to the BreachChecker interface.
type BreachCheckerFunc func(ctx context.Context, password string) (bool, error)

// IsBreached calls f.
func (f BreachCheckerFunc) IsBreached(ctx context.Context, password string) (bool, error) {
	return f(ctx, password)
}
