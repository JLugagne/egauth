package oauth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAuditPoc_UnsignedStateCookieAccepted demonstrates that the OAuth state
// cookie has NO integrity protection unless the host opts into
// WithStateSigningKey: an attacker who can plant a cookie (e.g. a sibling
// subdomain tossing a non-__Host- "oauth_state" cookie) can forge an
// arbitrary, well-formed state value without ever performing a Begin round
// trip, and unpackState accepts it. The forged state then flows into
// CallbackHandler's stateMatches comparison against the attacker's own
// authorization-response link (classic login-CSRF shape).
func TestAuditPoc_UnsignedStateCookieAccepted(t *testing.T) {
	// Attacker crafts a cookie carrying THEIR state/verifier/nonce — no signing
	// key involved, no Begin request needed.
	forged := packState("attacker-state", "attacker-verifier", "attacker-nonce", "google", "tenant-a")
	state, verifier, _, provider, tenant, ok := unpackState(forged)
	require.True(t, ok, "VULNERABILITY DEMONSTRATED: unsigned forged state cookie is accepted")
	require.Equal(t, "attacker-state", state)
	require.Equal(t, "attacker-verifier", verifier)
	require.Equal(t, "google", provider)
	require.Equal(t, "tenant-a", tenant)

	// With the opt-in signing key, the same forgery fails closed.
	signed := packState("s", "v", "n", "google", "tenant-a", []byte("host-signing-key-32-bytes-long!!!!"))
	_, _, _, _, _, ok = unpackState(signed, []byte("host-signing-key-32-bytes-long!!!!"))
	require.True(t, ok, "sanity: genuinely signed cookie verifies")
	_, _, _, _, _, ok = unpackState(forged, []byte("host-signing-key-32-bytes-long!!!!"))
	require.False(t, ok, "signed mode rejects the unsigned forgery")
}
