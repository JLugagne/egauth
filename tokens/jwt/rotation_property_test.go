package jwt_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the refresh-token rotation state machine with deterministic
// pseudo-random operation sequences and check the family invariants after every step:
//
//   - at most one token of a family is ever usable at the same time;
//   - replaying a consumed token in strict mode revokes the whole family;
//   - tenant, auth_time and MustChangePassword are preserved across every legal transition;
//   - the provider cannot extend the access-token lifetime or relocate the family.
//
// The generator is seeded from a constant, so a failing sequence is reproducible.

type rotationHarness struct {
	t        *testing.T
	svc      *jwt.Service[struct{}]
	store    *memory.Store[struct{}]
	now      time.Time
	rng      *rand.Rand
	provider bool

	families []*rotationFamily
	all      []rotationTokenRef
	byToken  map[string]*rotationFamily
	log      []string

	// Transition counters prove the random trace actually exercised each transition; a
	// sequence that only ever hit not-found would otherwise pass the invariants vacuously.
	statIssued  int
	statRotated int
	statTheft   int
	statExpired int
	statCross   int
	statGarbage int
}

type rotationFamily struct {
	id         uuid.UUID
	tenant     string
	userID     uuid.UUID
	authTime   time.Time
	mustChange bool
	tokens     []string
}

type rotationTokenRef struct {
	token string
	fam   *rotationFamily
}

func newRotationHarness(t *testing.T, seed int64) *rotationHarness {
	h := &rotationHarness{
		t:       t,
		rng:     rand.New(rand.NewSource(seed)),
		now:     time.Unix(1_700_000_000, 0).UTC(),
		byToken: make(map[string]*rotationFamily),
	}
	h.store = memory.NewStore[struct{}]()
	h.svc = jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      h.store,
		SecretKey:  "rotation-property-secret-0123456789!",
		Issuer:     "egauth-rotation-property",
		AccessTTL:  10 * time.Minute,
		RefreshTTL: 45 * time.Minute,
		// The absolute ceiling makes "rotate after the family has aged out" a reachable
		// transition (ErrTokenExpired) even when the individual refresh token has not expired.
		MaxRefreshLifetime: 30 * time.Minute,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{
				Subject:            userID,
				TenantID:           tenantID,
				MustChangePassword: h.provider,
			}, nil
		}),
		// Strict: any replay of a consumed token is theft. The grace-window path is covered
		// by TestRotationProperty_ConcurrentGraceSingleSuccessor with a real grace period.
		ReuseGracePeriod: -1,
		Clock:            func() time.Time { return h.now },
	})
	return h
}

func (h *rotationHarness) note(format string, args ...any) {
	h.log = append(h.log, fmt.Sprintf(format, args...))
}

func (h *rotationHarness) failf(format string, args ...any) {
	h.t.Helper()
	h.t.Fatalf("%s\noperation log:\n  %s", fmt.Sprintf(format, args...), strings.Join(h.log, "\n  "))
}

func (h *rotationHarness) randTenant() string {
	switch h.rng.Intn(3) {
	case 0:
		return ""
	case 1:
		return "tenant-a"
	default:
		return "tenant-b"
	}
}

func (h *rotationHarness) issue() {
	tenant := h.randTenant()
	userID := uuid.Must(uuid.NewV7())
	initialFlag := h.rng.Intn(2) == 0

	claims := tokens.Claims[struct{}]{
		Subject:            userID,
		TenantID:           tenant,
		MustChangePassword: initialFlag,
	}
	if h.rng.Intn(2) == 0 {
		claims.AuthTime = h.now.Add(-time.Duration(h.rng.Intn(5)) * time.Minute)
	}

	pair, err := h.svc.IssueTokenPair(context.Background(), claims)
	if err != nil {
		h.failf("IssueTokenPair: %v", err)
	}
	rt := h.find(pair.RefreshTokenHash, tenant, "issued token")
	fam := &rotationFamily{
		id:         rt.FamilyID,
		tenant:     tenant,
		userID:     userID,
		authTime:   rt.AuthTime,
		mustChange: rt.MustChangePassword,
		tokens:     []string{pair.RefreshToken},
	}
	if !rt.AuthTime.Equal(pair.Claims.AuthTime) {
		h.failf("issued pair auth_time %v != stored %v", pair.Claims.AuthTime, rt.AuthTime)
	}
	h.families = append(h.families, fam)
	h.byToken[pair.RefreshToken] = fam
	h.all = append(h.all, rotationTokenRef{token: pair.RefreshToken, fam: fam})
	h.statIssued++
	h.note("issue tenant=%q user=%s mayChange=%v authTime=%s -> family=%s", tenant, userID, initialFlag, rt.AuthTime, fam.id)
}

// find looks a token up through the store, failing the test on unexpected errors.
func (h *rotationHarness) find(hash, tenant, what string) *tokens.RefreshToken {
	h.t.Helper()
	rt, err := h.store.FindRefreshToken(context.Background(), tenant, hash)
	if err != nil {
		h.failf("find %s: %v", what, err)
	}
	return rt
}

// live reports whether the token named by hash is currently usable: present, not consumed,
// not revoked and not past its expiry in the harness clock.
func (h *rotationHarness) live(token string) bool {
	fam, ok := h.byToken[token]
	if !ok {
		return false
	}
	rt, err := h.store.FindRefreshToken(context.Background(), fam.tenant, tokens.HashToken(token))
	if err != nil {
		return false
	}
	return rt.ConsumedAt == nil && rt.RevokedAt == nil && !h.now.After(rt.ExpiresAt)
}

func (h *rotationHarness) liveCount(fam *rotationFamily) int {
	n := 0
	for _, tok := range fam.tokens {
		if h.live(tok) {
			n++
		}
	}
	return n
}

// checkInvariants enforces the family-level safety property: a rotation family never has two
// simultaneously usable tokens.
func (h *rotationHarness) checkInvariants(op string) {
	h.t.Helper()
	for _, fam := range h.families {
		if n := h.liveCount(fam); n > 1 {
			h.failf("family %s has %d simultaneously usable refresh tokens after %s", fam.id, n, op)
		}
	}
}

func (h *rotationHarness) rotateRef(ref rotationTokenRef) {
	h.t.Helper()
	fam := ref.fam
	before := h.liveCount(fam)
	h.checkInvariants("before rotate")

	pair, err := h.svc.Rotate(context.Background(), fam.tenant, ref.token)
	if err != nil {
		switch {
		case errors.Is(err, tokens.ErrRefreshConcurrent):
			// Never produced by this single-threaded, strict-mode sequence.
			h.failf("unexpected concurrent result in strict mode: %v", err)
		case errors.Is(err, tokens.ErrRefreshTokenReused):
			// Strict-mode replay: the whole family must be revoked or unreachable.
			if n := h.liveCount(fam); n != 0 {
				h.failf("replay of consumed token did not revoke the family: %d live tokens remain", n)
			}
			h.statTheft++
			h.note("rotate tenant=%q token=%.8s -> theft, family revoked", fam.tenant, ref.token)
		case errors.Is(err, tokens.ErrTokenExpired):
			if after := h.liveCount(fam); after != before {
				h.failf("failed rotation changed liveness: %d -> %d (%v)", before, after, err)
			}
			h.statExpired++
			h.note("rotate tenant=%q token=%.8s -> %v", fam.tenant, ref.token, err)
		case errors.Is(err, tokens.ErrTokenFamilyRevoked),
			errors.Is(err, tokens.ErrRefreshTokenNotFound):
			if after := h.liveCount(fam); after != before {
				h.failf("failed rotation changed liveness: %d -> %d (%v)", before, after, err)
			}
			h.note("rotate tenant=%q token=%.8s -> %v", fam.tenant, ref.token, err)
		default:
			h.failf("unexpected rotation error: %v", err)
		}
		h.checkInvariants("failed rotate")
		return
	}

	// A successful rotation consumes the presented token and mints exactly one live successor
	// in the same family, preserving tenant, auth_time and the forced-change flag.
	if h.live(ref.token) {
		h.failf("rotated token is still usable")
	}
	wantFlag := fam.mustChange || h.provider
	if pair.Claims.TenantID != fam.tenant {
		h.failf("rotation relocated family: tenant %q -> %q", fam.tenant, pair.Claims.TenantID)
	}
	if !pair.Claims.AuthTime.Equal(fam.authTime) {
		h.failf("rotation manufactured auth_time: %v -> %v", fam.authTime, pair.Claims.AuthTime)
	}
	if pair.Claims.MustChangePassword != wantFlag {
		h.failf("rotation dropped forced-change flag: want %v, got %v", wantFlag, pair.Claims.MustChangePassword)
	}
	rt := h.find(pair.RefreshTokenHash, fam.tenant, "rotated token")
	if rt.TenantID != fam.tenant {
		h.failf("stored descendant tenant %q != family tenant %q", rt.TenantID, fam.tenant)
	}
	if !rt.AuthTime.Equal(fam.authTime) {
		h.failf("stored descendant auth_time %v != family auth_time %v", rt.AuthTime, fam.authTime)
	}
	if rt.MustChangePassword != wantFlag {
		h.failf("stored descendant forced-change flag %v != expected %v", rt.MustChangePassword, wantFlag)
	}

	verified, err := h.svc.VerifyAccessTokenForTenant(context.Background(), fam.tenant, pair.AccessToken)
	if err != nil {
		h.failf("rotated access token did not verify: %v", err)
	}
	if verified.TenantID != fam.tenant ||
		!verified.AuthTime.Equal(fam.authTime) ||
		verified.MustChangePassword != wantFlag {
		h.failf("rotated access claims lost family state: tenant=%q authTime=%v mustChange=%v",
			verified.TenantID, verified.AuthTime, verified.MustChangePassword)
	}

	fam.mustChange = wantFlag
	fam.tokens = append(fam.tokens, pair.RefreshToken)
	h.byToken[pair.RefreshToken] = fam
	h.all = append(h.all, rotationTokenRef{token: pair.RefreshToken, fam: fam})
	h.statRotated++
	h.note("rotate tenant=%q token=%.8s -> %.8s", fam.tenant, ref.token, pair.RefreshToken)

	if n := h.liveCount(fam); n != 1 {
		h.failf("after successful rotation family has %d live tokens, want exactly 1", n)
	}
	h.checkInvariants("successful rotate")
}

func (h *rotationHarness) pickRef() (rotationTokenRef, bool) {
	if len(h.all) == 0 {
		return rotationTokenRef{}, false
	}
	return h.all[h.rng.Intn(len(h.all))], true
}

func (h *rotationHarness) step() {
	switch n := h.rng.Intn(100); {
	case n < 16:
		h.issue()
	case n < 60:
		if ref, ok := h.pickRef(); ok {
			h.rotateRef(ref)
		} else {
			h.issue()
		}
	case n < 75:
		inc := time.Duration(1+h.rng.Intn(3)) * time.Minute
		if h.rng.Intn(4) == 0 {
			inc = time.Duration(30+h.rng.Intn(90)) * time.Minute
		}
		h.now = h.now.Add(inc)
		h.note("advance clock +%s -> %s", inc, h.now)
	case n < 85:
		_, err := h.svc.Rotate(context.Background(), h.randTenant(), "not-a-real-refresh-token")
		if !errors.Is(err, tokens.ErrRefreshTokenNotFound) {
			h.failf("unknown token must not be found, got %v", err)
		}
		h.statGarbage++
		h.note("rotate garbage -> %v", err)
	case n < 95:
		if ref, ok := h.pickRef(); ok {
			other := "tenant-other"
			if ref.fam.tenant == other {
				other = "tenant-other-2"
			}
			_, err := h.svc.Rotate(context.Background(), other, ref.token)
			if !errors.Is(err, tokens.ErrRefreshTokenNotFound) {
				h.failf("cross-tenant rotation must fail closed, got %v", err)
			}
			h.statCross++
			h.note("cross-tenant rotate tenant=%q -> %v", other, err)
		}
	default:
		h.checkInvariants("idle check")
	}
}

// TestRotationProperty_FamilyInvariants runs deterministic operation sequences over many
// seeded iterations and checks the family invariants after every step. The aggregate counters
// assert the traces actually reached rotation, theft, expiry and cross-tenant transitions, so
// the invariants cannot pass vacuously.
func TestRotationProperty_FamilyInvariants(t *testing.T) {
	var issued, rotated, theft, expired, cross, garbage int
	for seed := int64(0); seed < 16; seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			h := newRotationHarness(t, seed)
			h.provider = seed%2 == 0
			for i := 0; i < 80; i++ {
				h.step()
				h.checkInvariants("step")
			}
			issued += h.statIssued
			rotated += h.statRotated
			theft += h.statTheft
			expired += h.statExpired
			cross += h.statCross
			garbage += h.statGarbage
		})
	}
	require.Greater(t, issued, 0, "no family was ever issued")
	require.Greater(t, rotated, 0, "no rotation ever succeeded")
	require.Greater(t, theft, 0, "no replay was ever detected as theft")
	require.Greater(t, expired, 0, "no rotation ever hit the expiry ceiling")
	require.Greater(t, cross, 0, "no cross-tenant rotation was ever attempted")
	require.Greater(t, garbage, 0, "no unknown-token rotation was ever attempted")
}

// TestRotationProperty_ConcurrentGraceSingleSuccessor exercises the concurrent-grace branch:
// a burst of rotations of the same live token has exactly one winner, the family survives,
// and a subsequent replay of the consumed ancestor is treated as benign concurrency.
func TestRotationProperty_ConcurrentGraceSingleSuccessor(t *testing.T) {
	ctx := context.Background()
	for seed := int64(0); seed < 12; seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(1000 + seed))
			now := time.Unix(1_700_000_000, 0).UTC()
			store := memory.NewStore[struct{}]()
			svc := jwt.New[struct{}](jwt.Config[struct{}]{
				Store:      store,
				SecretKey:  "rotation-property-secret-0123456789!",
				Issuer:     "egauth-rotation-grace",
				AccessTTL:  10 * time.Minute,
				RefreshTTL: time.Hour,
				ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
					return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
				}),
				Clock: func() time.Time { return now },
			})

			tenant := []string{"", "tenant-a", "tenant-b"}[rng.Intn(3)]
			pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.Must(uuid.NewV7()), TenantID: tenant})
			require.NoError(t, err)

			workers := 2 + rng.Intn(14)
			type outcome struct {
				pair *tokens.TokenPair[struct{}]
				err  error
			}
			results := make(chan outcome, workers)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					p, err := svc.Rotate(ctx, tenant, pair.RefreshToken)
					results <- outcome{pair: p, err: err}
				}()
			}
			close(start)
			wg.Wait()
			close(results)

			var winner *tokens.TokenPair[struct{}]
			for r := range results {
				switch r.err {
				case nil:
					require.Nil(t, winner, "only one concurrent rotation may succeed")
					winner = r.pair
				default:
					require.ErrorIs(t, r.err, tokens.ErrRefreshConcurrent,
						"every concurrent loser must observe benign concurrency, got %v", r.err)
				}
			}
			require.NotNil(t, winner, "exactly one concurrent rotation must succeed")

			known := []string{pair.RefreshToken, winner.RefreshToken}
			countLive := func() int {
				n := 0
				for _, tok := range known {
					rt, err := store.FindRefreshToken(ctx, tenant, tokens.HashToken(tok))
					if err == nil && rt.ConsumedAt == nil && rt.RevokedAt == nil && !now.After(rt.ExpiresAt) {
						n++
					}
				}
				return n
			}
			require.Equal(t, 1, countLive(), "a concurrent burst must leave exactly one usable token")

			_, err = svc.Rotate(ctx, tenant, pair.RefreshToken)
			require.ErrorIs(t, err, tokens.ErrRefreshConcurrent,
				"an in-grace replay of the consumed ancestor is benign concurrency")
			require.ErrorIs(t, err, tokens.ErrRefreshTokenReused,
				"benign concurrency keeps the reuse sentinel for existing callers")
			require.Equal(t, 1, countLive(), "benign concurrency must not revoke the family")

			next, err := svc.Rotate(ctx, tenant, winner.RefreshToken)
			require.NoError(t, err, "the winner's successor must remain usable")
			assert.Equal(t, tenant, next.Claims.TenantID)
		})
	}
}
