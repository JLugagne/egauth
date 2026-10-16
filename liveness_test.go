package egauth_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/limiter"
)

type allowEverything struct{ limiterStub }

func (allowEverything) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{Allowed: true}, nil
}

type failingLimiter struct{ limiterStub }

func (failingLimiter) Allow(context.Context, limiter.Key) (limiter.Decision, error) {
	return limiter.Decision{}, errors.New("limiter store down")
}

type countingMFA struct {
	mfaStub
	legacy, enrolled int64
}

func (s countingMFA) CountLegacySealed(context.Context) (int64, error) { return s.legacy, nil }
func (s countingMFA) AnyEnrolled(context.Context) (bool, error)        { return s.enrolled > 0, nil }
func (s countingMFA) CountEnrolled(context.Context) (int64, error)     { return s.enrolled, nil }

type countingPasskeys struct {
	passkeyStub
	enrolled int64
}

func (s countingPasskeys) AnyEnrolled(context.Context) (bool, error)    { return s.enrolled > 0, nil }
func (s countingPasskeys) CountEnrolled(context.Context) (int64, error) { return s.enrolled, nil }

type countingFederation struct {
	federationStub
	legacy int64
}

func (s countingFederation) CountLegacySealed(context.Context) (int64, error) { return s.legacy, nil }

type countingKeys struct {
	keysStub
	legacy int64
}

func (s countingKeys) CountLegacySealed(context.Context) (int64, error) { return s.legacy, nil }

type blockingIdentity struct{ identityStub }

func (blockingIdentity) Ping(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

type flakyIdentity struct {
	identityStub
	fail *atomic.Bool
}

func (s flakyIdentity) EpochsChangedSince(ctx context.Context, c store.Cursor) ([]identity.EpochChange, store.Cursor, error) {
	if s.fail.Load() {
		return nil, c, errors.New("feed down")
	}
	return s.Store.EpochsChangedSince(ctx, c)
}

func derivedKEK(t testing.TB, label string, previous ...string) *kek.Local {
	t.Helper()
	key := func(l string) []byte {
		sum := sha256.Sum256([]byte("egauth liveness test " + l))
		return sum[:]
	}
	var prev [][]byte
	for _, p := range previous {
		prev = append(prev, key(p))
	}
	k, err := kek.NewLocal(key(label), prev...)
	require.NoError(t, err)
	return k
}

func TestLivenessSchemaCheckPingsEveryStore(t *testing.T) {
	cfg := fullConfig(t)
	failing := errors.New("migration 007 missing")
	st := cfg.Storage
	for _, b := range []*base{
		st.Identity.(identityStub).b, st.Ceremonies.(ceremonyStub).b, st.Deployment.(deploymentStub).b, st.Limiter.(limiterStub).b,
		st.Tokens.(tokensStub).b, st.Sessions.(sessionsStub).b, st.MFA.(mfaStub).b, st.Passkeys.(passkeyStub).b,
		st.Federation.(federationStub).b, st.Keys.(keysStub).b, cfg.RateLimit.(limiterStub).b,
	} {
		b.err = failing
	}
	err := newErr(t, cfg)
	require.ErrorContains(t, err, "migration 007 missing")
	for _, f := range []string{"Storage.Identity", "Storage.Ceremonies", "Storage.Deployment", "Storage.Limiter", "Storage.Tokens",
		"Storage.Sessions", "Storage.MFA", "Storage.Passkeys", "Storage.Federation", "Storage.Keys", "RateLimit"} {
		requireField(t, err, f)
	}
}

func TestLivenessKEKCanaryCreatesThenOpens(t *testing.T) {
	cfg := minimalConfig(t)
	cfg.KEK = derivedKEK(t, "one")
	first := mustNew(t, cfg)
	sealed, err := cfg.Storage.Deployment.GetSealed(context.Background(), "datakey")
	require.NoError(t, err, "New creates the canary")
	second := mustNew(t, cfg)
	require.Equal(t, egauth.OwnedOf(first).DataKey, egauth.OwnedOf(second).DataKey, "every instance of a deployment shares one data key")
	again, err := cfg.Storage.Deployment.GetSealed(context.Background(), "datakey")
	require.NoError(t, err)
	require.Equal(t, sealed, again, "an opened canary is left as it is")
}

func TestLivenessKEKCanaryRefusesAWrongKey(t *testing.T) {
	cfg := minimalConfig(t)
	cfg.KEK = derivedKEK(t, "one")
	mustNew(t, cfg)
	cfg.KEK = derivedKEK(t, "other")
	err := newErr(t, cfg)
	requireField(t, err, "KEK")
	require.ErrorContains(t, err, "cannot open existing data (wrong or rotated-out key)")
}

func TestLivenessKEKCanaryOpensARotatedKeyAndReseals(t *testing.T) {
	cfg := minimalConfig(t)
	cfg.KEK = derivedKEK(t, "one")
	old := mustNew(t, cfg)
	cfg.KEK = derivedKEK(t, "two", "one")
	rotated := mustNew(t, cfg)
	require.Equal(t, egauth.OwnedOf(old).DataKey, egauth.OwnedOf(rotated).DataKey)
	sealed, err := cfg.Storage.Deployment.GetSealed(context.Background(), "datakey")
	require.NoError(t, err)
	id, err := cfg.KEK.KeyIDOf(sealed)
	require.NoError(t, err)
	require.Equal(t, cfg.KEK.CurrentKeyID(), id, "the canary follows the current key")
}

func TestLivenessRefusesV016SecretsLeftInPlace(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Storage.MFA = countingMFA{mfaStub: cfg.Storage.MFA.(mfaStub), legacy: 4}
	cfg.Storage.Federation = countingFederation{federationStub: cfg.Storage.Federation.(federationStub), legacy: 3}
	cfg.Storage.Keys = countingKeys{keysStub: cfg.Storage.Keys.(keysStub), legacy: 2}
	err := newErr(t, cfg)
	requireField(t, err, "Storage")
	require.ErrorContains(t, err, "9 v0.16 secrets not upgraded; run egauth.UpgradeSecretsV016")
}

type countingIdentity struct {
	identityStub
	legacy int64
}

func (s countingIdentity) CountLegacyIdentifiers(context.Context) (int64, error) {
	return s.legacy, nil
}

func TestLivenessRefusesUncheckedV016Identifiers(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Storage.Identity = countingIdentity{identityStub: cfg.Storage.Identity.(identityStub), legacy: 5}
	err := newErr(t, cfg)
	requireField(t, err, "Storage.Identity")
	require.ErrorContains(t, err, "5 v0.16 accounts with unchecked identifiers; run egauth.UpgradeIdentifiersV016")
}

func TestLivenessRefusesEnrolledFactorsWhoseModuleIsAbsent(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Modules.MFA = nil
	cfg.Storage.MFA = countingMFA{mfaStub: cfg.Storage.MFA.(mfaStub), enrolled: 3}
	err := newErr(t, cfg)
	requireField(t, err, "Modules.MFA")
	require.ErrorContains(t, err, "TOTP enrolled for 3 subjects but Modules.MFA is nil")

	cfg = fullConfig(t)
	cfg.Modules.Passkey = nil
	cfg.Storage.Passkeys = countingPasskeys{passkeyStub: cfg.Storage.Passkeys.(passkeyStub), enrolled: 2}
	err = newErr(t, cfg)
	requireField(t, err, "Modules.Passkey")
	require.ErrorContains(t, err, "passkeys enrolled for 2 subjects but Modules.Passkey is nil")
}

func TestLivenessAcceptsEnrollmentsWhenTheirModuleIsPresent(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Storage.MFA = countingMFA{mfaStub: cfg.Storage.MFA.(mfaStub), enrolled: 3}
	cfg.Storage.Passkeys = countingPasskeys{passkeyStub: cfg.Storage.Passkeys.(passkeyStub), enrolled: 2}
	require.NoError(t, newErr(t, cfg))
}

func TestLivenessAcceptsAnEmptyStoreWithoutTheModules(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Modules.MFA, cfg.Modules.Passkey = nil, nil
	require.NoError(t, newErr(t, cfg))
}

func TestLivenessLimiterProbeRefusesALimiterThatEnforcesNothing(t *testing.T) {
	cfg := fullConfig(t)
	cfg.RateLimit = allowEverything{memLimiter(store.Shared)}
	err := newErr(t, cfg)
	requireField(t, err, "RateLimit")
	require.ErrorContains(t, err, "enforces no budget")
}

func TestLivenessLimiterProbeReportsAFailingLimiter(t *testing.T) {
	cfg := fullConfig(t)
	cfg.RateLimit = failingLimiter{memLimiter(store.Shared)}
	err := newErr(t, cfg)
	requireField(t, err, "RateLimit")
	require.ErrorContains(t, err, "limiter store down")
}

func TestLivenessLimiterProbeIsSkippedByTheOptOutAndLeavesNoTrace(t *testing.T) {
	cfg := fullConfig(t)
	cfg.RateLimit = allowEverything{memLimiter(store.Shared)}
	cfg.Insecure.NoRateLimit = egauth.Acknowledge("rate limiting is done by the gateway")
	require.NoError(t, newErr(t, cfg))
}

func TestLivenessEveryBlockingCallIsBoundedByTheStartupTimeout(t *testing.T) {
	require.Equal(t, 30*time.Second, egauth.StartupTimeout)
	restore := egauth.SetStartupTimeout(150 * time.Millisecond)
	defer restore()
	cfg := fullConfig(t)
	cfg.Storage.Identity = blockingIdentity{cfg.Storage.Identity.(identityStub)}
	began := time.Now()
	err := newErr(t, cfg)
	require.Less(t, time.Since(began), 5*time.Second)
	requireField(t, err, "Storage.Identity")
	require.ErrorContains(t, err, "deadline exceeded")
}

func TestLivenessOAuthDiscoveryRunsThroughTheOutboundGuard(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Modules.OAuth.Providers = []federation.Provider{{Name: "oidc", ClientID: "client", Issuer: "https://127.0.0.1:9"}}
	rec := &dialRecorder{}
	cfg.Outbound = rec
	err := newErr(t, cfg)
	requireField(t, err, "Modules.OAuth")
	require.ErrorContains(t, err, "discovery failed")
	var blocked bool
	for _, e := range rec.failures() {
		blocked = blocked || (e != nil && strings.Contains(e.Error(), "blocked address (SSRF guard)"))
	}
	require.True(t, blocked, "the loopback issuer must be refused by the dial guard: %v", rec.failures())
}

func TestLivenessRouteTableIsMountedOnAThrowawayMux(t *testing.T) {
	first := mustNew(t, fullConfig(t))
	second := mustNew(t, fullConfig(t))
	require.Equal(t, egauth.OwnedOf(first).Patterns, egauth.OwnedOf(second).Patterns)
	_, pattern := http.DefaultServeMux.Handler(&http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/auth/login"}})
	require.Empty(t, pattern, "the route table never touches the process-wide mux")
}

func TestLivenessAnUnmountableBasePathIsAConfigErrorNotAPanic(t *testing.T) {
	cfg := fullConfig(t)
	cfg.BasePath = "/auth/../x"
	err := newErr(t, cfg)
	require.Error(t, err)
	requireField(t, err, "BasePath")
}

func sharedDeployment(t *testing.T, d store.Durability) egauth.Storage {
	t.Helper()
	return storage(d)
}

func ephemeralLimiterConfig(t *testing.T, shared egauth.Storage, sink event.Sink) egauth.Config[struct{}] {
	t.Helper()
	cfg := minimalConfig(t)
	cfg.Storage = shared
	cfg.Storage.Limiter = memLimiter(store.Ephemeral)
	cfg.Events = sink
	return cfg
}

func allowedUntilDenied(t *testing.T, a *egauth.Auth[struct{}], value string) int {
	t.Helper()
	l := egauth.OwnedOf(a).Limiter
	for n := 0; n < 100; n++ {
		d, err := l.Allow(context.Background(), limiter.Key{Class: limiter.LoginClient, Value: value})
		require.NoError(t, err)
		if !d.Allowed {
			return n
		}
	}
	t.Fatal("the limiter never denied")
	return 0
}

func TestLivenessEphemeralLimiterBesideSharedStoresIsScaledByTheLiveInstances(t *testing.T) {
	shared := sharedDeployment(t, store.Shared)
	sink1, sink2 := &wiringSink{}, &wiringSink{}
	first := mustNew(t, ephemeralLimiterConfig(t, shared, sink1))
	require.Equal(t, 1, first.Posture().Instances)
	require.Equal(t, limiter.LoginClient.Budget().Burst, allowedUntilDenied(t, first, "198.51.100.1"))
	require.Len(t, sink1.of(event.LimiterPerInstance), 1, "the opt-in to per-instance limiting is announced once")

	second := mustNew(t, ephemeralLimiterConfig(t, shared, sink2))
	require.Equal(t, 2, second.Posture().Instances)
	require.Equal(t, limiter.LoginClient.Budget().Burst/2, allowedUntilDenied(t, second, "198.51.100.2"))
	got := sink2.of(event.LimiterPerInstance)
	require.Len(t, got, 1)
	require.Equal(t, 2, got[0].Attrs[string(event.KeyCount)])

	require.NoError(t, egauth.Pulse(first))
	require.Equal(t, 2, first.Posture().Instances)
	require.Equal(t, limiter.LoginClient.Budget().Burst/2, allowedUntilDenied(t, first, "198.51.100.3"))
}

func TestLivenessASharedLimiterIsNotScaled(t *testing.T) {
	shared := sharedDeployment(t, store.Shared)
	sink := &wiringSink{}
	cfg := minimalConfig(t)
	cfg.Storage, cfg.Events = shared, sink
	mustNew(t, cfg)
	second := mustNew(t, cfg)
	require.Equal(t, 2, second.Posture().Instances)
	require.Empty(t, sink.of(event.LimiterPerInstance))
	require.Equal(t, limiter.LoginClient.Budget().Burst, allowedUntilDenied(t, second, "198.51.100.4"))
}

func TestLivenessSecondInstanceOnEphemeralStateMakesReadyFail(t *testing.T) {
	shared := storage(store.Ephemeral)
	cfg := minimalConfig(t)
	cfg.PublicOrigin = "http://localhost:8080"
	cfg.Storage = shared
	first := mustNew(t, cfg)
	require.NoError(t, first.Ready(context.Background()))
	second := mustNew(t, cfg)
	err := second.Ready(context.Background())
	require.ErrorContains(t, err, "second live instance")
	require.NoError(t, egauth.Pulse(first))
	require.ErrorContains(t, first.Ready(context.Background()), "second live instance")
}

func TestLivenessHeartbeatCountsEveryInstanceSharingTheDeployment(t *testing.T) {
	shared := sharedDeployment(t, store.Shared)
	cfg := minimalConfig(t)
	cfg.Storage = shared
	var all []*egauth.Auth[struct{}]
	for range 3 {
		all = append(all, mustNew(t, cfg))
	}
	require.NoError(t, egauth.Pulse(all[0]))
	require.Equal(t, 3, all[0].Posture().Instances)
	require.Equal(t, store.Shared, all[0].Posture().Durability)
}

func TestLivenessReadyReportsARevocationFeedThatStoppedAnswering(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for revoke.PollBound")
	}
	cfg := fullConfig(t)
	fail := &atomic.Bool{}
	cfg.Storage.Identity = flakyIdentity{identityStub: cfg.Storage.Identity.(identityStub), fail: fail}
	a := mustNew(t, cfg)
	require.NoError(t, a.Ready(context.Background()))
	fail.Store(true)
	require.Eventually(t, func() bool {
		err := a.Ready(context.Background())
		return err != nil && strings.Contains(err.Error(), "revocation cache is stale")
	}, 15*time.Second, 250*time.Millisecond)
	fail.Store(false)
	require.Eventually(t, func() bool { return a.Ready(context.Background()) == nil }, 15*time.Second, 250*time.Millisecond)
}

func TestLivenessNewDoesNotTouchTheStoresOfAnInvalidConfiguration(t *testing.T) {
	cfg := fullConfig(t)
	cfg.PublicOrigin = "http://app.example.com"
	failing := errors.New("must not be pinged")
	cfg.Storage.Identity.(identityStub).b.err = failing
	err := newErr(t, cfg)
	require.NotContains(t, err.Error(), failing.Error())
}

func TestLivenessReadyPingsACustomRateLimit(t *testing.T) {
	cfg := fullConfig(t)
	a := mustNew(t, cfg)
	require.NoError(t, a.Ready(context.Background()))
	failing := errors.New("limiter schema missing")
	cfg.RateLimit.(limiterStub).b.err = failing
	err := a.Ready(context.Background())
	require.ErrorIs(t, err, failing)
	require.ErrorContains(t, err, "RateLimit")
}

func TestLivenessMountConflictIsAnErrorNotAPanic(t *testing.T) {
	first, second := egauth.MountTwice(mustNew(t, fullConfig(t)))
	require.NoError(t, first)
	require.Error(t, second)
	require.ErrorIs(t, second, routes.ErrConflict)
}
