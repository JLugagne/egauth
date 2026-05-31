package jwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	oldSecret = "old-signing-secret-aaaaaaaaaaaaaaaaaaaa"
	newSecret = "new-signing-secret-bbbbbbbbbbbbbbbbbbbb"
)

func keysetService(t *testing.T, keys []jwt.SigningKey, active string) *jwt.Service[struct{}] {
	t.Helper()
	return jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
		SigningKeys:    keys,
		ActiveKeyID:    active,
	})
}

// kidOf returns the "kid" header of a JWT without verifying it.
func kidOf(t *testing.T, tokenStr string) string {
	t.Helper()
	tok, _, err := gojwt.NewParser().ParseUnverified(tokenStr, gojwt.MapClaims{})
	require.NoError(t, err)
	kid, _ := tok.Header["kid"].(string)
	return kid
}

func TestKeyset_TokenTaggedWithActiveKid(t *testing.T) {
	ctx := context.Background()
	svc := keysetService(t, []jwt.SigningKey{
		{KeyID: "k-old", Secret: oldSecret},
		{KeyID: "k-new", Secret: newSecret},
	}, "k-new")

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)
	assert.Equal(t, "k-new", kidOf(t, pair.AccessToken), "new tokens must carry the active kid")
}

func TestKeyset_RetiredKeyStillVerifiesDuringOverlap(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	// 1. Issue a token while "k-old" is the active key.
	svcOld := keysetService(t, []jwt.SigningKey{{KeyID: "k-old", Secret: oldSecret}}, "k-old")
	oldPair, err := svcOld.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)
	require.Equal(t, "k-old", kidOf(t, oldPair.AccessToken))

	// 2. Roll the key: "k-new" is now active, but "k-old" stays in the set for the overlap.
	svcNew := keysetService(t, []jwt.SigningKey{
		{KeyID: "k-old", Secret: oldSecret},
		{KeyID: "k-new", Secret: newSecret},
	}, "k-new")

	// The token signed by the retired key still verifies.
	claims, err := svcNew.VerifyAccessToken(ctx, oldPair.AccessToken)
	require.NoError(t, err, "a live token signed by the retired key must still verify during overlap")
	assert.Equal(t, userID, claims.Subject)

	// And freshly issued tokens use the new active key.
	freshPair, err := svcNew.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)
	assert.Equal(t, "k-new", kidOf(t, freshPair.AccessToken))
	_, err = svcNew.VerifyAccessToken(ctx, freshPair.AccessToken)
	require.NoError(t, err)
}

func TestKeyset_DroppingOldKeyRejectsItsTokens(t *testing.T) {
	ctx := context.Background()
	svcOld := keysetService(t, []jwt.SigningKey{{KeyID: "k-old", Secret: oldSecret}}, "k-old")
	oldPair, err := svcOld.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	// After the overlap window, "k-old" is dropped from the set entirely.
	svcNewOnly := keysetService(t, []jwt.SigningKey{{KeyID: "k-new", Secret: newSecret}}, "k-new")
	_, err = svcNewOnly.VerifyAccessToken(ctx, oldPair.AccessToken)
	require.ErrorIs(t, err, tokens.ErrInvalidToken, "a token whose kid was retired must be rejected")
}

func TestKeyset_UnknownKidRejected(t *testing.T) {
	ctx := context.Background()
	// Sign a token with a key id that the verifier does not know.
	stranger := keysetService(t, []jwt.SigningKey{{KeyID: "k-stranger", Secret: oldSecret}}, "k-stranger")
	pair, err := stranger.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	svc := keysetService(t, []jwt.SigningKey{{KeyID: "k-new", Secret: newSecret}}, "k-new")
	_, err = svc.VerifyAccessToken(ctx, pair.AccessToken)
	require.ErrorIs(t, err, tokens.ErrInvalidToken)
}

func TestKeyset_LegacyTokenVerifiesAfterEnablingRotation(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	// 1. A token minted in single-key (legacy) mode carries no kid.
	svcLegacy := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		SecretKey:      oldSecret,
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
	})
	legacyPair, err := svcLegacy.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)
	require.Empty(t, kidOf(t, legacyPair.AccessToken), "legacy tokens are kid-less")

	// 2. Rotation enabled, but the old SecretKey is kept as the legacy verification key.
	svcRotated := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		SecretKey:      oldSecret, // kept as legacy verifier
		SigningKeys:    []jwt.SigningKey{{KeyID: "k-new", Secret: newSecret}},
		ActiveKeyID:    "k-new",
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
	})

	// The kid-less legacy token still verifies via the legacy key.
	claims, err := svcRotated.VerifyAccessToken(ctx, legacyPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.Subject)

	// New tokens are tagged with the active kid.
	freshPair, err := svcRotated.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID})
	require.NoError(t, err)
	assert.Equal(t, "k-new", kidOf(t, freshPair.AccessToken))
}

func TestKeyset_KidlessTokenRejectedWithoutLegacyKey(t *testing.T) {
	ctx := context.Background()
	// Legacy token (no kid).
	svcLegacy := jwt.New[struct{}](jwt.Config[struct{}]{
		Store: memory.NewStore[struct{}](), SecretKey: oldSecret, Issuer: "egauth-test",
		AccessTTL: 5 * time.Minute, RefreshTTL: 24 * time.Hour, ClaimsProvider: okProvider(t),
	})
	legacyPair, err := svcLegacy.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	// Pure keyset, no legacy SecretKey: a kid-less token has no key to verify against.
	svcKeyset := keysetService(t, []jwt.SigningKey{{KeyID: "k-new", Secret: newSecret}}, "k-new")
	_, err = svcKeyset.VerifyAccessToken(ctx, legacyPair.AccessToken)
	require.ErrorIs(t, err, tokens.ErrInvalidToken)
}

func TestKeyset_RotateRefreshAcrossKeyChange(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore[struct{}]()

	// Issue under the old active key.
	svcOld := jwt.New[struct{}](jwt.Config[struct{}]{
		Store: store, Issuer: "egauth-test", AccessTTL: 5 * time.Minute, RefreshTTL: 24 * time.Hour,
		ClaimsProvider: okProvider(t),
		SigningKeys:    []jwt.SigningKey{{KeyID: "k-old", Secret: oldSecret}}, ActiveKeyID: "k-old",
	})
	pair, err := svcOld.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	// Same store, key rolled to new. Rotating the (opaque) refresh token yields a pair signed
	// with the new key, and the rotation family is preserved.
	svcNew := jwt.New[struct{}](jwt.Config[struct{}]{
		Store: store, Issuer: "egauth-test", AccessTTL: 5 * time.Minute, RefreshTTL: 24 * time.Hour,
		ClaimsProvider: okProvider(t),
		SigningKeys:    []jwt.SigningKey{{KeyID: "k-old", Secret: oldSecret}, {KeyID: "k-new", Secret: newSecret}},
		ActiveKeyID:    "k-new",
	})
	rotated, err := svcNew.Rotate(ctx, pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "k-new", kidOf(t, rotated.AccessToken))
	_, err = svcNew.VerifyAccessToken(ctx, rotated.AccessToken)
	require.NoError(t, err)
}

func TestKeyset_MalformedKidRejected(t *testing.T) {
	ctx := context.Background()
	// Rotation enabled but the legacy SecretKey is kept (the documented overlap state).
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          memory.NewStore[struct{}](),
		SecretKey:      oldSecret, // legacy verifier present
		SigningKeys:    []jwt.SigningKey{{KeyID: "k-new", Secret: newSecret}},
		ActiveKeyID:    "k-new",
		Issuer:         "egauth-test",
		AccessTTL:      5 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		ClaimsProvider: okProvider(t),
	})

	// Hand-craft a token signed with the legacy key but carrying a PRESENT kid that is not a
	// non-empty string. Such a token must NOT be passed off as "kid-less" and verified against
	// the legacy key — a present kid header always selects the kid path.
	makeToken := func(kid any) string {
		claims := gojwt.MapClaims{
			"sub": uuid.New().String(),
			"iss": "egauth-test",
			"exp": float64(time.Now().Add(time.Hour).Unix()),
			"iat": float64(time.Now().Add(-time.Minute).Unix()),
		}
		tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString([]byte(oldSecret))
		require.NoError(t, err)
		return s
	}

	t.Run("numeric kid", func(t *testing.T) {
		_, err := svc.VerifyAccessToken(ctx, makeToken(12345))
		require.ErrorIs(t, err, tokens.ErrInvalidToken)
	})
	t.Run("empty-string kid", func(t *testing.T) {
		_, err := svc.VerifyAccessToken(ctx, makeToken(""))
		require.ErrorIs(t, err, tokens.ErrInvalidToken)
	})
}

func TestNew_PanicsOnMalformedKeyset(t *testing.T) {
	base := func(keys []jwt.SigningKey, active string) jwt.Config[struct{}] {
		return jwt.Config[struct{}]{
			Store: memory.NewStore[struct{}](), Issuer: "egauth-test",
			AccessTTL: time.Minute, RefreshTTL: time.Hour, SigningKeys: keys, ActiveKeyID: active,
		}
	}
	t.Run("entry without KeyID", func(t *testing.T) {
		assert.Panics(t, func() { jwt.New[struct{}](base([]jwt.SigningKey{{Secret: newSecret}}, "")) })
	})
	t.Run("multiple keys without ActiveKeyID", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.New[struct{}](base([]jwt.SigningKey{{KeyID: "a", Secret: oldSecret}, {KeyID: "b", Secret: newSecret}}, ""))
		})
	})
	t.Run("ActiveKeyID not in set", func(t *testing.T) {
		assert.Panics(t, func() { jwt.New[struct{}](base([]jwt.SigningKey{{KeyID: "a", Secret: oldSecret}}, "missing")) })
	})
	t.Run("no key at all", func(t *testing.T) {
		assert.Panics(t, func() {
			jwt.New[struct{}](jwt.Config[struct{}]{Store: memory.NewStore[struct{}](), Issuer: "x", AccessTTL: time.Minute, RefreshTTL: time.Hour})
		})
	})
}

func TestValidate_Keyset(t *testing.T) {
	good := jwt.Config[struct{}]{
		Issuer: "egauth-test", AccessTTL: time.Minute, RefreshTTL: time.Hour,
		SigningKeys: []jwt.SigningKey{{KeyID: "k-new", Secret: newSecret}}, ActiveKeyID: "k-new",
	}
	require.NoError(t, good.Validate())

	t.Run("short secret in set", func(t *testing.T) {
		cfg := good
		cfg.SigningKeys = []jwt.SigningKey{{KeyID: "k", Secret: "too-short"}}
		cfg.ActiveKeyID = "k"
		require.Error(t, cfg.Validate())
	})
	t.Run("duplicate key id", func(t *testing.T) {
		cfg := good
		cfg.SigningKeys = []jwt.SigningKey{{KeyID: "dup", Secret: oldSecret}, {KeyID: "dup", Secret: newSecret}}
		cfg.ActiveKeyID = "dup"
		require.Error(t, cfg.Validate())
	})
	t.Run("active not in set", func(t *testing.T) {
		cfg := good
		cfg.ActiveKeyID = "nope"
		require.Error(t, cfg.Validate())
	})
}
