package outbound_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/outbound"
)

func loopbackAllowance(t *testing.T) outbound.Allowance {
	t.Helper()
	a, err := outbound.NewAllowance([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	require.NoError(t, err)
	return a
}

func get(t *testing.T, c *outbound.Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := c.Do(req)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	return resp, err
}

func okServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestStaticScopeReachesLoopbackOnlyThroughItsAllowance(t *testing.T) {
	srv, hits := okServer(t)
	clients := outbound.New(outbound.Config{Static: loopbackAllowance(t)})

	resp, err := get(t, clients.Static(), srv.URL+"/jwks")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "ok", string(body))
	require.EqualValues(t, 1, hits.Load())
}

func TestTenantScopeDoesNotInheritTheStaticAllowance(t *testing.T) {
	srv, hits := okServer(t)
	clients := outbound.New(outbound.Config{Static: loopbackAllowance(t)})

	_, err := get(t, clients.Tenant(), srv.URL+"/jwks")
	require.Error(t, err)
	require.Zero(t, hits.Load(), "the tenant scope must never reach a network only the operator allowed")
}

func TestEmptyAllowanceBlocksLoopbackAtDialTime(t *testing.T) {
	srv, hits := okServer(t)
	clients := outbound.New(outbound.Config{Tenant: loopbackAllowance(t)})

	tlsURL := "https" + srv.URL[len("http"):]
	_, err := get(t, clients.Static(), tlsURL)
	require.ErrorIs(t, err, outbound.ErrBlockedAddress)
	require.Zero(t, hits.Load())
}

func TestLiteralMetadataAddressesAreBlocked(t *testing.T) {
	allowance, err := outbound.NewAllowance([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	require.NoError(t, err)
	clients := outbound.New(outbound.Config{Static: allowance, Tenant: allowance})
	urls := []string{
		"https://169.254.169.254/latest/meta-data/",
		"https://[::ffff:169.254.169.254]/latest/meta-data/",
		"https://100.100.100.200/latest/meta-data/",
		"https://168.63.129.16/machine",
		"https://0.0.0.0/",
	}
	for _, c := range []*outbound.Client{clients.Static(), clients.Tenant()} {
		for _, u := range urls {
			_, err := get(t, c, u)
			require.ErrorIs(t, err, outbound.ErrBlockedAddress, u)
		}
	}
}

func TestPlainHTTPToMetadataIsRefusedBeforeAnyDial(t *testing.T) {
	clients := outbound.New(outbound.Config{})
	_, err := get(t, clients.Static(), "http://169.254.169.254/latest/meta-data/")
	require.ErrorIs(t, err, outbound.ErrInsecureScheme)
}

func TestPlainHTTPNeedsAnAllowedLiteralAddress(t *testing.T) {
	clients := outbound.New(outbound.Config{Static: loopbackAllowance(t)})
	for _, u := range []string{"http://example.com/", "http://93.184.216.34/", "ftp://127.0.0.1/", "http://localhost/"} {
		_, err := get(t, clients.Static(), u)
		require.ErrorIs(t, err, outbound.ErrInsecureScheme, u)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var followed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(http.ResponseWriter, *http.Request) {
		followed.Add(1)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	clients := outbound.New(outbound.Config{Static: loopbackAllowance(t)})

	_, err := get(t, clients.Static(), srv.URL+"/start")
	require.ErrorIs(t, err, outbound.ErrRedirect)
	require.Zero(t, followed.Load())
}

func TestProxyEnvironmentIsIgnored(t *testing.T) {
	proxy, proxyHits := okServer(t)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	clients := outbound.New(outbound.Config{Static: loopbackAllowance(t)})

	_, err := get(t, clients.Static(), "https://169.254.169.254/")
	require.ErrorIs(t, err, outbound.ErrBlockedAddress)
	require.Zero(t, proxyHits.Load())
}

type recordingObserver struct {
	mu       sync.Mutex
	starts   []*http.Request
	statuses []int
	errs     []error
}

func (o *recordingObserver) OutboundStart(req *http.Request) func(*http.Response, error) {
	o.mu.Lock()
	o.starts = append(o.starts, req)
	o.mu.Unlock()
	req.Header.Set("X-Injected", "1")
	req.URL.Path = "/hijacked"
	return func(resp *http.Response, err error) {
		o.mu.Lock()
		defer o.mu.Unlock()
		if resp != nil {
			o.statuses = append(o.statuses, resp.StatusCode)
			_, _ = io.ReadAll(resp.Body)
		}
		o.errs = append(o.errs, err)
	}
}

func TestObserverSeesARedactedCopyAndCannotAlterTheRequest(t *testing.T) {
	var seenPath, seenInjected string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath, seenInjected = r.URL.Path, r.Header.Get("X-Injected")
		_, _ = io.WriteString(w, "payload")
	}))
	t.Cleanup(srv.Close)
	obs := &recordingObserver{}
	clients := outbound.New(outbound.Config{Static: loopbackAllowance(t), Observer: obs})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/token?code=secret", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Basic c2VjcmV0")
	req.Header.Set("Cookie", "a=b")
	req.Header.Set("Accept", "application/json")
	resp, err := clients.Static().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, "payload", string(body), "the observer must not consume the caller's body")
	require.Equal(t, "/token", seenPath)
	require.Empty(t, seenInjected)
	require.Len(t, obs.starts, 1)
	seen := obs.starts[0]
	require.Empty(t, seen.Header.Get("Authorization"))
	require.Empty(t, seen.Header.Get("Cookie"))
	require.Equal(t, "application/json", seen.Header.Get("Accept"))
	require.Empty(t, seen.URL.RawQuery)
	require.Equal(t, []int{http.StatusOK}, obs.statuses)
	require.Equal(t, []error{nil}, obs.errs)
}

func TestObserverIsToldAboutBlockedDials(t *testing.T) {
	obs := &recordingObserver{}
	clients := outbound.New(outbound.Config{Observer: obs})
	_, err := get(t, clients.Static(), "https://169.254.169.254/")
	require.ErrorIs(t, err, outbound.ErrBlockedAddress)
	require.Len(t, obs.errs, 1)
	require.ErrorIs(t, obs.errs[0], outbound.ErrBlockedAddress)
}

func TestZeroClientRefuses(t *testing.T) {
	var c outbound.Client
	_, err := get(t, &c, "https://example.com/")
	require.ErrorIs(t, err, outbound.ErrZeroClient)
	var nilClient *outbound.Client
	_, err = get(t, nilClient, "https://example.com/")
	require.ErrorIs(t, err, outbound.ErrZeroClient)
}

func TestNilRequestIsRefused(t *testing.T) {
	clients := outbound.New(outbound.Config{})
	_, err := clients.Static().Do(nil)
	require.Error(t, err)
}

func TestCloseIdleReleasesBothScopes(t *testing.T) {
	srv, _ := okServer(t)
	clients := outbound.New(outbound.Config{Static: loopbackAllowance(t), Observer: &recordingObserver{}})
	resp, err := get(t, clients.Static(), srv.URL)
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body)
	clients.CloseIdle()
	_, err = get(t, clients.Static(), srv.URL)
	require.NoError(t, err)
}
