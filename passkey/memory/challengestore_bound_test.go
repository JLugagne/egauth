// Regression test for F-PASSKEY-002: the expiry index must stay bounded by the live-entry
// cap even under a Begin/Finish cycling flood. Consume (and a re-Put of the same key) must
// remove the index row, not leave it for the TTL window; otherwise an unauthenticated caller
// grows the index with request volume regardless of MaxChallenges.
package memory

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestChallengeStore_ExpiryIndexStaysBoundedUnderCycling drives Put/Consume cycles far past
// the cap and asserts the retained expiry-index rows stay within a small multiple of the cap.
func TestChallengeStore_ExpiryIndexStaysBoundedUnderCycling(t *testing.T) {
	const (
		max    = 64
		cycles = 20_000
	)
	s := NewChallengeStore(WithMaxChallenges(max))
	ctx := context.Background()
	expiry := time.Now().Add(5 * time.Minute)

	for i := 0; i < cycles; i++ {
		ch := fmt.Sprintf("challenge-%d", i)
		require.NoError(t, s.Put(ctx, "tenant", ch, expiry))
		ok, err := s.Consume(ctx, "tenant", ch)
		require.NoError(t, err)
		require.True(t, ok)
	}

	require.Equal(t, 0, s.Len(), "every challenge was consumed")
	require.LessOrEqual(t, s.expiry.Len(), 3*max,
		"the expiry index must stay bounded by MaxChallenges, not grow with request volume")
}

// TestChallengeStore_ExpiryIndexStaysBoundedOnReplacement covers the other leak path: a
// re-Put of an existing key replaces its entry, and the superseded index row must not linger.
func TestChallengeStore_ExpiryIndexStaysBoundedOnReplacement(t *testing.T) {
	const (
		max     = 4
		repeats = 1000
	)
	s := NewChallengeStore(WithMaxChallenges(max))
	ctx := context.Background()
	expiry := time.Now().Add(5 * time.Minute)

	for i := 0; i < repeats; i++ {
		require.NoError(t, s.Put(ctx, "tenant", "same-challenge", expiry.Add(time.Duration(i)*time.Second)))
	}

	require.Equal(t, 1, s.Len(), "a re-Put replaces the entry")
	require.LessOrEqual(t, s.expiry.Len(), 3*max,
		"replacing a challenge must not accumulate index rows")
}
