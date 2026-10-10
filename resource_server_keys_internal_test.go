package egauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
)

func verifierFor(t *testing.T, kid string) signing.Verifier {
	t.Helper()
	sum := sha256.Sum256([]byte("jwks source " + kid))
	s, err := signing.EdDSA(kid, sum[:])
	require.NoError(t, err)
	return s.Verifier()
}

type jwksFixture struct {
	clk   *clock.Test
	src   *jwksSource
	calls int
	keys  []signing.Verifier
	err   error
}

func newJWKSFixture(t *testing.T, kids ...string) *jwksFixture {
	t.Helper()
	f := &jwksFixture{clk: clock.NewTest(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))}
	for _, k := range kids {
		f.keys = append(f.keys, verifierFor(t, k))
	}
	f.src = &jwksSource{clk: f.clk.Clock(), fetch: func(context.Context) ([]signing.Verifier, error) {
		f.calls++
		return f.keys, f.err
	}}
	require.NoError(t, f.src.refresh(context.Background(), f.clk.Now()))
	f.calls = 0
	return f
}

func (f *jwksFixture) get(kid string) error {
	_, err := f.src.Verifier(context.Background(), principal.TenantID{}, kid)
	return err
}

func TestResourceServerJWKSSourceServesKnownKeysWithoutFetching(t *testing.T) {
	f := newJWKSFixture(t, "a", "b")
	require.NoError(t, f.get("a"))
	require.NoError(t, f.get("b"))
	require.Zero(t, f.calls)
}

func TestResourceServerJWKSSourceRefreshesOnAnUnknownKeyIdAtMostOncePerInterval(t *testing.T) {
	f := newJWKSFixture(t, "a")
	require.ErrorIs(t, f.get("rotated"), errUnknownKeyID)
	require.Zero(t, f.calls, "a fresh set is not refetched for a forged key id")

	f.clk.Advance(jwksMinRefresh)
	f.keys = append(f.keys, verifierFor(t, "rotated"))
	require.NoError(t, f.get("rotated"))
	require.Equal(t, 1, f.calls)

	f.clk.Advance(jwksMinRefresh)
	require.ErrorIs(t, f.get("ghost"), errUnknownKeyID)
	require.Equal(t, 2, f.calls)
	require.ErrorIs(t, f.get("ghost2"), errUnknownKeyID)
	require.Equal(t, 2, f.calls, "refetches are rate limited")
}

func TestResourceServerJWKSSourceDropsAKeyTheIssuerStoppedPublishing(t *testing.T) {
	f := newJWKSFixture(t, "a", "b")
	f.clk.Advance(jwksMaxAge)
	f.keys = f.keys[:1]
	require.NoError(t, f.get("a"))
	require.ErrorIs(t, f.get("b"), errUnknownKeyID)
}

func TestResourceServerJWKSSourceFailsClosedWhenItsSetIsTooOldToRefresh(t *testing.T) {
	f := newJWKSFixture(t, "a")
	f.clk.Advance(jwksMaxAge)
	f.err = errors.New("auth down")
	err := f.get("a")
	require.ErrorIs(t, err, revoke.ErrUnavailable)
	require.Equal(t, 1, f.calls)
	require.ErrorIs(t, f.get("a"), revoke.ErrUnavailable)
	require.Equal(t, 1, f.calls, "an outage is not retried before the interval")

	f.clk.Advance(jwksMinRefresh)
	f.err = nil
	require.NoError(t, f.get("a"))
}

func TestResourceServerJWKSSourceTreatsAClockThatMovedBackAsStale(t *testing.T) {
	f := newJWKSFixture(t, "a")
	f.clk.Advance(-time.Hour)
	require.NoError(t, f.get("a"))
	require.Equal(t, 1, f.calls)
}

func TestResourceServerJWKSSourceIgnoresAClientThatHungUp(t *testing.T) {
	f := newJWKSFixture(t, "a")
	f.clk.Advance(jwksMaxAge)
	f.src.fetch = func(ctx context.Context) ([]signing.Verifier, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return f.keys, nil
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.src.Verifier(gone, principal.TenantID{}, "a")
	require.ErrorIs(t, err, revoke.ErrUnavailable)
	require.NoError(t, f.get("a"), "a hung up client must not poison the key set for everyone")
}

func TestResourceServerJWKSSourceDoesNotHoldItsLockDuringAFetch(t *testing.T) {
	f := newJWKSFixture(t, "a")
	release := make(chan struct{})
	started := make(chan struct{})
	f.clk.Advance(jwksMinRefresh)
	f.src.fetch = func(context.Context) ([]signing.Verifier, error) {
		close(started)
		<-release
		return f.keys, nil
	}
	done := make(chan error, 1)
	go func() { done <- f.get("unknown") }()
	<-started
	require.NoError(t, f.get("a"), "a known key on a fresh set is served while a fetch is in flight")
	close(release)
	require.ErrorIs(t, <-done, errUnknownKeyID)
}

func TestResourceServerJWKSSourceRefusesAnotherTenantWithoutFetching(t *testing.T) {
	f := newJWKSFixture(t, "a")
	f.src.tenant = "acme"
	f.clk.Advance(jwksMaxAge)
	other, err := principal.ParseTenantID("other")
	require.NoError(t, err)
	_, err = f.src.Verifier(context.Background(), other, "a")
	require.ErrorIs(t, err, errUnknownKeyID)
	require.Zero(t, f.calls)
	_, err = f.src.Verifier(context.Background(), principal.TenantID{}, "a")
	require.ErrorIs(t, err, errUnknownKeyID)
}

func TestResourceServerJWKSMaxAgeBoundsKeyRevocationLatency(t *testing.T) {
	require.LessOrEqual(t, jwksMaxAge, time.Minute)
}

func TestResourceServerFetchKeysAcceptsAnEmptySetAsEveryKeyRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)
	allow, err := outbound.NewAllowance([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	require.NoError(t, err)
	rs := &ResourceServer[struct{}]{outbound: outbound.New(outbound.Config{Static: allow})}
	vs, err := rs.fetchKeys(context.Background(), srv.URL)
	require.NoError(t, err)
	require.Empty(t, vs)

	f := newJWKSFixture(t, "a")
	f.keys = nil
	f.clk.Advance(jwksMaxAge)
	require.ErrorIs(t, f.get("a"), errUnknownKeyID)
}
