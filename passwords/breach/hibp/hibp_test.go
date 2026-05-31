package hibp_test

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/breach/hibp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sha1Hex returns the uppercase hex SHA-1 of s, split into the 5-char range prefix and the
// 35-char suffix exactly as the HIBP range API uses them.
func sha1Hex(s string) (prefix, suffix string) {
	sum := sha1.Sum([]byte(s))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	return full[:5], full[5:]
}

// rangeServer returns an httptest server that serves the HIBP range API for one password: for
// the matching prefix it returns the password's suffix with the given count (plus some decoy
// lines and zero-count padding). It records the last requested path so tests can assert that
// only the 5-char prefix — never the suffix — left the process.
func rangeServer(t *testing.T, password string, count int) (*httptest.Server, *string) {
	t.Helper()
	wantPrefix, wantSuffix := sha1Hex(password)
	var lastPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		assert.Equal(t, "/range/"+wantPrefix, r.URL.Path, "only the 5-char prefix may be queried")
		assert.NotEmpty(t, r.Header.Get("User-Agent"), "HIBP requires a User-Agent")
		var b strings.Builder
		// Decoy real entry + zero-count padding entry that must never count as a match.
		fmt.Fprintf(&b, "%s:%d\r\n", strings.Repeat("A", 35), 9999)
		fmt.Fprintf(&b, "%s:%d\r\n", strings.Repeat("B", 35), 0)
		if count > 0 {
			// HIBP returns the suffix in uppercase; serve lowercase to prove case-insensitivity.
			fmt.Fprintf(&b, "%s:%d\r\n", strings.ToLower(wantSuffix), count)
		}
		_, _ = w.Write([]byte(b.String()))
	}))
	t.Cleanup(srv.Close)
	return srv, &lastPath
}

func TestClient_IsBreached_FoundSendsOnlyPrefix(t *testing.T) {
	const pw = "Sup3rSecret-passphrase!"
	srv, lastPath := rangeServer(t, pw, 42)

	c := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()))
	breached, err := c.IsBreached(context.Background(), pw)
	require.NoError(t, err)
	assert.True(t, breached, "a suffix present with a positive count is breached")

	wantPrefix, wantSuffix := sha1Hex(pw)
	assert.Equal(t, "/range/"+wantPrefix, *lastPath)
	assert.NotContains(t, *lastPath, wantSuffix, "the suffix must never leave the process")
}

func TestClient_IsBreached_NotFound(t *testing.T) {
	const pw = "a-genuinely-unique-passphrase-9182"
	// count 0 => the server omits our suffix entirely, only decoy/padding lines remain.
	srv, _ := rangeServer(t, pw, 0)

	c := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()))
	breached, err := c.IsBreached(context.Background(), pw)
	require.NoError(t, err)
	assert.False(t, breached)
}

func TestClient_IsBreached_PaddingZeroCountNeverMatches(t *testing.T) {
	// A zero-count line (HIBP Add-Padding decoy) carrying our suffix must not count as breached.
	const pw = "padding-collision-test-pw"
	wantPrefix, wantSuffix := sha1Hex(pw)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/range/"+wantPrefix, r.URL.Path)
		fmt.Fprintf(w, "%s:0\r\n", wantSuffix) // suffix present but count 0 (padding)
	}))
	t.Cleanup(srv.Close)

	c := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()))
	breached, err := c.IsBreached(context.Background(), pw)
	require.NoError(t, err)
	assert.False(t, breached, "zero-count padding entries must not be treated as a breach")
}

func TestClient_Threshold(t *testing.T) {
	const pw = "seen-a-few-times-pw"
	srv, _ := rangeServer(t, pw, 5)

	// Below threshold: not breached.
	strict := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()), hibp.WithThreshold(10))
	breached, err := strict.IsBreached(context.Background(), pw)
	require.NoError(t, err)
	assert.False(t, breached, "count 5 is below threshold 10")

	// At/above threshold: breached.
	lax := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()), hibp.WithThreshold(5))
	breached, err = lax.IsBreached(context.Background(), pw)
	require.NoError(t, err)
	assert.True(t, breached, "count 5 meets threshold 5")
}

func TestClient_FailClosed_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()))
	_, err := c.IsBreached(context.Background(), "whatever")
	require.Error(t, err, "by default an upstream failure propagates (the policy then fails closed)")
}

func TestClient_FailOpen_SwallowsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	c := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()), hibp.WithFailOpen())
	breached, err := c.IsBreached(context.Background(), "whatever")
	require.NoError(t, err, "fail-open swallows the upstream error")
	assert.False(t, breached, "fail-open treats an unreachable service as not-breached")
}

func TestClient_OversizedResponseFailsClosed(t *testing.T) {
	// A response larger than the client's internal cap, whose matching line falls beyond the cap,
	// must surface as an error — never a silent "not breached" (which would let a known-breached
	// password through, even under the fail-closed default).
	const pw = "oversized-response-pw"
	wantPrefix, wantSuffix := sha1Hex(pw)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/range/"+wantPrefix, r.URL.Path)
		// ~5.4 MiB of zero-count padding (> the 4 MiB cap), THEN the real match last.
		_, _ = io.WriteString(w, strings.Repeat(strings.Repeat("A", 35)+":0\n", 140_000))
		_, _ = io.WriteString(w, strings.ToLower(wantSuffix)+":777\n")
	}))
	t.Cleanup(srv.Close)

	c := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()))
	_, err := c.IsBreached(context.Background(), pw)
	require.Error(t, err, "an oversized/truncated response must error, not silently report not-breached")
}

func TestClient_LargeLineWithinCapIsParsed(t *testing.T) {
	// A single line larger than bufio's default 64 KiB token cap (but within the response cap)
	// must not error — the match on a later line must still be found.
	const pw = "large-line-pw"
	wantPrefix, wantSuffix := sha1Hex(pw)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/range/"+wantPrefix, r.URL.Path)
		_, _ = io.WriteString(w, strings.Repeat("A", 100*1024)+"\r\n") // 100 KiB junk, no ':' -> skipped
		_, _ = io.WriteString(w, strings.ToLower(wantSuffix)+":12\r\n")
	}))
	t.Cleanup(srv.Close)

	c := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()))
	breached, err := c.IsBreached(context.Background(), pw)
	require.NoError(t, err, "a line larger than 64 KiB but within the response cap must not error")
	assert.True(t, breached)
}

func TestClient_RespectsContextCancellation(t *testing.T) {
	srv, _ := rangeServer(t, "ctx-pw-123456", 1)
	c := hibp.New(hibp.WithBaseURL(srv.URL), hibp.WithHTTPClient(srv.Client()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	_, err := c.IsBreached(ctx, "ctx-pw-123456")
	require.Error(t, err)
}

// The client must satisfy the passwords.BreachChecker hook so it drops straight into the policy.
var _ passwords.BreachChecker = (*hibp.Client)(nil)
