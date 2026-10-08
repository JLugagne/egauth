package outbound_test

import (
	"context"
	"go/build"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/outbound"
)

func TestNewAllowanceRejectsTheOracleCloudMetadataAddress(t *testing.T) {
	for _, raw := range []string{"192.0.0.192/32", "192.0.0.0/24", "192.0.0.128/25"} {
		_, err := outbound.NewAllowance(prefixes(t, raw))
		require.ErrorIs(t, err, outbound.ErrInvalidAllowance, raw)
	}
	var zero outbound.Allowance
	require.False(t, zero.Permits(netip.MustParseAddr("192.0.0.192")))
}

func TestNewAllowanceRejectsTransitionRanges(t *testing.T) {
	for _, raw := range []string{"2002::/16", "2002:a00::/24", "2001::/32"} {
		_, err := outbound.NewAllowance(prefixes(t, raw))
		require.ErrorIs(t, err, outbound.ErrInvalidAllowance, raw)
	}
}

func TestTransitionAddressesAreJudgedByTheirEmbeddedIPv4(t *testing.T) {
	var zero outbound.Allowance
	blocked := []string{
		"2002:a9fe:a9fe::1",
		"2002:0a00:0001::1",
		"2002:7f00:0001::1",
		"2001:0:4136:e378:8000:63bf:5601:5601",
		"2001:0:0a00:0001:8000:63bf:3fff:fdd2",
	}
	for _, raw := range blocked {
		require.False(t, zero.Permits(netip.MustParseAddr(raw)), raw)
	}
	require.True(t, zero.Permits(netip.MustParseAddr("2002:0808:0808::1")))
	require.True(t, zero.Permits(netip.MustParseAddr("2001:0:4136:e378:8000:63bf:f7f7:f7f7")))

	private, err := outbound.NewAllowance(prefixes(t, "10.0.0.0/8"))
	require.NoError(t, err)
	require.True(t, private.Permits(netip.MustParseAddr("2002:0a00:0001::1")))
	require.False(t, private.Permits(netip.MustParseAddr("2002:a9fe:a9fe::1")))
}

type panickingObserver struct {
	inStart bool
}

func (o panickingObserver) OutboundStart(*http.Request) func(*http.Response, error) {
	if o.inStart {
		panic("observer start")
	}
	return func(*http.Response, error) { panic("observer done") }
}

func TestObserverPanicsDoNotReachTheRequestPath(t *testing.T) {
	srv, hits := okServer(t)
	for _, inStart := range []bool{true, false} {
		clients := outbound.New(outbound.Config{Static: loopbackAllowance(t), Observer: panickingObserver{inStart: inStart}})
		var resp *http.Response
		var err error
		require.NotPanics(t, func() { resp, err = get(t, clients.Static(), srv.URL) })
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "ok", string(body))
	}
	require.EqualValues(t, 2, hits.Load())
}

type urlObserver struct {
	mu   sync.Mutex
	urls []string
	done int
}

func (o *urlObserver) OutboundStart(req *http.Request) func(*http.Response, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.urls = append(o.urls, req.URL.String())
	return func(*http.Response, error) {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.done++
	}
}

func TestDoSecretPathHidesThePathFromTheObserver(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	obs := &urlObserver{}
	clients := outbound.New(outbound.Config{Static: loopbackAllowance(t), Observer: obs})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/range/5BAA6", nil)
	require.NoError(t, err)
	resp, err := clients.Static().DoSecretPath(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, "/range/5BAA6", seenPath)

	_, err = get(t, clients.Static(), srv.URL+"/jwks")
	require.NoError(t, err)

	require.Equal(t, []string{srv.URL, srv.URL + "/jwks"}, obs.urls)
	require.Equal(t, 2, obs.done)
}

func TestDoSecretPathKeepsTheGuards(t *testing.T) {
	clients := outbound.New(outbound.Config{})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://169.254.169.254/range/5BAA6", nil)
	require.NoError(t, err)
	_, err = clients.Static().DoSecretPath(req)
	require.ErrorIs(t, err, outbound.ErrBlockedAddress)

	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/range/5BAA6", nil)
	require.NoError(t, err)
	_, err = clients.Static().DoSecretPath(req)
	require.ErrorIs(t, err, outbound.ErrInsecureScheme)

	var zero outbound.Client
	_, err = zero.DoSecretPath(req)
	require.ErrorIs(t, err, outbound.ErrZeroClient)
}

func TestDoSecretPathHidesThePathFromTheCallerError(t *testing.T) {
	clients := outbound.New(outbound.Config{})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://127.0.0.1:9/range/ABCDE?q=SECRET#FRAG", nil)
	require.NoError(t, err)
	_, err = clients.Static().DoSecretPath(req)
	require.ErrorIs(t, err, outbound.ErrBlockedAddress)
	require.NotContains(t, err.Error(), "ABCDE")
	require.NotContains(t, err.Error(), "range")
	require.NotContains(t, err.Error(), "SECRET")
	require.NotContains(t, err.Error(), "FRAG")
	var ue *url.Error
	require.ErrorAs(t, err, &ue)
	require.Equal(t, "https://127.0.0.1:9", ue.URL)
	require.Equal(t, "https://127.0.0.1:9/range/ABCDE?q=SECRET#FRAG", req.URL.String())
}

func TestZeroAllowanceBlocksNonGlobalSpecialPurposeRanges(t *testing.T) {
	var zero outbound.Allowance
	for _, raw := range []string{
		"fec0::1",
		"2001:2::1",
		"2001:10::1",
		"2001:20::1",
		"3fff::1",
		"5f00::1",
		"192.88.99.1",
	} {
		require.False(t, zero.Permits(netip.MustParseAddr(raw)), raw)
	}
}

func TestProductionCodeDoesNotLinkTheTestingPackage(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	require.NoError(t, err)
	require.NotContains(t, pkg.Imports, "testing")
}
