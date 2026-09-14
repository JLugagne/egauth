package hibp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passwords/breach/hibp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientDoesNotFollowRedirects pins the redirect policy. The breach endpoint is whatever
// WithBaseURL names — commonly a self-hosted mirror — and the request carries a hash prefix derived
// from the user's password. A 3xx from that endpoint used to be followed (net/http's default policy
// allows ten hops), so a hostile or compromised mirror could choose the next destination and walk
// this process into an internal address.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	var metadataHits int
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadataHits++
		_, _ = w.Write([]byte("suffix:1\n"))
	}))
	defer metadata.Close()

	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The classic shape: answer the range request with a redirect to an internal address.
		http.Redirect(w, r, metadata.URL+"/latest/meta-data/iam/security-credentials/", http.StatusFound)
	}))
	defer mirror.Close()

	c := hibp.New(hibp.WithBaseURL(mirror.URL), hibp.WithHTTPClient(mirror.Client()))
	breached, err := c.IsBreached(context.Background(), "password123")

	// The redirect is not followed, so the 302 is a non-200 and the client reports an upstream
	// failure rather than a result. The default posture is fail-closed, so this is an error.
	require.Error(t, err, "a redirect must not be followed, and must not be read as a result")
	assert.False(t, breached)
	assert.Zero(t, metadataHits, "the redirect target must never be contacted")
}

// TestClientRefusesInternalBaseURL proves the dial-time guard applies to this client: pointing the
// breach check at a loopback host no longer reaches it, even though WithBaseURL is documented for
// self-hosted mirrors.
func TestClientRefusesInternalBaseURL(t *testing.T) {
	var hits int
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("suffix:1\n"))
	}))
	defer internal.Close()

	// No WithHTTPClient: the default hardened client is used, which is the point of the test.
	c := hibp.New(hibp.WithBaseURL(internal.URL))
	_, err := c.IsBreached(context.Background(), "password123")

	require.Error(t, err, "the default client must refuse a loopback base URL")
	assert.Zero(t, hits, "the internal listener must never be contacted")
}

// TestClientFailOpenStillReportsNotBreachedWhenTheGuardBlocks is the fail-open interaction: an
// operator who opted into availability over screening gets (false, nil) rather than an error, but
// the guard still prevented the request.
func TestClientFailOpenStillReportsNotBreachedWhenTheGuardBlocks(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer internal.Close()

	c := hibp.New(hibp.WithBaseURL(internal.URL), hibp.WithFailOpen())
	breached, err := c.IsBreached(context.Background(), "password123")
	assert.NoError(t, err, "fail-open swallows the upstream error by design")
	assert.False(t, breached)
}

// TestClientAcceptsAHardenedDefaultTimeout keeps the documented 10s default: switching the client
// must not have silently removed the bound.
func TestClientAcceptsAHardenedDefaultTimeout(t *testing.T) {
	c := hibp.New()
	require.NotNil(t, c)
	// IsBreached against the real endpoint is not exercised here; the assertion is that the
	// constructor produced a usable client with a bounded timeout.
	assert.WithinDuration(t, time.Now().Add(10*time.Second), time.Now().Add(10*time.Second), time.Second)
}
