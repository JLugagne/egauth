package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/JLugagne/libauth/tokens"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// claimsWrapper wraps the standard JWT claims and our custom generic claims.
type claimsWrapper[C any] struct {
	jwt.RegisteredClaims
	TenantID string   `json:"tenant_id,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	Custom   C        `json:"custom"`
}

// DefaultReuseGracePeriod is the window after a refresh token is consumed during which a
// replay of that same token is treated as benign concurrency (e.g. parallel tabs, link
// prefetch, or several sub-resource requests racing to rotate the same cookie) rather than
// theft. It mirrors the "refresh token reuse leeway" used by mainstream identity providers
// to avoid logging users out on ordinary request concurrency.
const DefaultReuseGracePeriod = 10 * time.Second

// Service provides JWT-based implementations of tokens.Issuer, tokens.Verifier and
// tokens.Rotator.
type Service[C any] struct {
	store          tokens.Store[C]
	claimsProvider tokens.ClaimsProvider[C]
	secretKey      []byte
	issuer         string
	accessTTL      time.Duration
	refreshTTL     time.Duration
	refreshLength  int
	apiKeyLength   int
	reuseGrace     time.Duration
}

// Config defines the configuration for the JWT Service.
type Config[C any] struct {
	Store     tokens.Store[C]
	SecretKey string
	Issuer    string
	// ClaimsProvider resolves fresh claims during refresh-token rotation. It is required
	// for Rotate; IssueTokenPair / IssueAPIKey do not need it.
	ClaimsProvider tokens.ClaimsProvider[C]
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	RefreshLength  int
	APIKeyLength   int
	// ReuseGracePeriod tunes refresh-token reuse detection. A replay of a consumed token
	// within this window is treated as benign concurrency (rejected without revoking the
	// family); a replay after it is treated as theft and revokes the whole family. The zero
	// value selects DefaultReuseGracePeriod; set a negative value for strict mode, where any
	// replay of a consumed token revokes the family.
	ReuseGracePeriod time.Duration
}

// New creates a new JWT Service.
func New[C any](cfg Config[C]) *Service[C] {
	if cfg.RefreshLength == 0 {
		cfg.RefreshLength = 32
	}
	if cfg.APIKeyLength == 0 {
		cfg.APIKeyLength = 32
	}
	if cfg.ReuseGracePeriod == 0 {
		cfg.ReuseGracePeriod = DefaultReuseGracePeriod
	}

	return &Service[C]{
		store:          cfg.Store,
		claimsProvider: cfg.ClaimsProvider,
		secretKey:      []byte(cfg.SecretKey),
		issuer:         cfg.Issuer,
		accessTTL:      cfg.AccessTTL,
		refreshTTL:     cfg.RefreshTTL,
		refreshLength:  cfg.RefreshLength,
		apiKeyLength:   cfg.APIKeyLength,
		reuseGrace:     cfg.ReuseGracePeriod,
	}
}

// IssueTokenPair generates a new Access and Refresh token pair for the given claims,
// starting a fresh rotation family.
func (s *Service[C]) IssueTokenPair(ctx context.Context, claims tokens.Claims[C]) (*tokens.TokenPair[C], error) {
	return s.issuePair(ctx, claims, uuid.New())
}

// issuePair signs an access JWT and mints an opaque refresh token, persisting the refresh
// token (hash only) within the given family. It is shared by initial issuance (new family)
// and rotation (existing family).
func (s *Service[C]) issuePair(ctx context.Context, claims tokens.Claims[C], familyID uuid.UUID) (*tokens.TokenPair[C], error) {
	now := time.Now()
	accessExpiresAt := now.Add(s.accessTTL)
	if !claims.ExpiresAt.IsZero() {
		accessExpiresAt = claims.ExpiresAt
	}

	wrapper := claimsWrapper[C]{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   claims.Subject.String(),
			Audience:  claims.Audiences,
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		TenantID: claims.TenantID,
		Scopes:   claims.Scopes,
		Groups:   claims.Groups,
		Roles:    claims.Roles,
		AMR:      claims.AMR,
		Custom:   claims.Custom,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, wrapper)
	accessTokenStr, err := token.SignedString(s.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Generate opaque refresh token.
	refreshBytes := make([]byte, s.refreshLength)
	if _, err := rand.Read(refreshBytes); err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshTokenStr := base64.RawURLEncoding.EncodeToString(refreshBytes)
	refreshHash := tokens.HashToken(refreshTokenStr)
	refreshExpiresAt := now.Add(s.refreshTTL)

	rt := &tokens.RefreshToken{
		Hash:      refreshHash,
		FamilyID:  familyID,
		UserID:    claims.Subject,
		TenantID:  claims.TenantID,
		ExpiresAt: refreshExpiresAt,
		CreatedAt: now,
	}

	if err := s.store.SaveRefreshToken(ctx, rt, tokens.WithTenant(claims.TenantID)); err != nil {
		return nil, err
	}

	// Reflect the issuer-controlled access expiry back into the returned claims.
	claims.ExpiresAt = accessExpiresAt

	return &tokens.TokenPair[C]{
		AccessToken:           accessTokenStr,
		RefreshToken:          refreshTokenStr,
		RefreshTokenHash:      refreshHash,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
		Claims:                claims,
	}, nil
}

// Rotate consumes the presented refresh token and issues a fresh pair within the same
// family. A replayed (already-consumed) token triggers revocation of the whole family.
func (s *Service[C]) Rotate(ctx context.Context, refreshToken string, opts ...tokens.Option) (*tokens.TokenPair[C], error) {
	if s.claimsProvider == nil {
		return nil, tokens.ErrNoClaimsProvider
	}

	hash := tokens.HashToken(refreshToken)

	rt, err := s.store.FindRefreshToken(ctx, hash, opts...)
	if err != nil {
		return nil, err
	}

	// A consumed token was presented again. Within the reuse grace window this is treated
	// as benign concurrency (the legitimate client raced itself): the request is rejected
	// but the family is kept alive. Outside the window it is treated as theft — a stale
	// token resurfacing long after it was rotated away — and the whole family is revoked so
	// every descendant is invalidated. If the revocation itself fails we must NOT report a
	// clean reuse rejection (which the caller treats as "theft handled"); surface the
	// failure so the family is never silently assumed revoked. Wrapping keeps
	// errors.Is(…Reused) true for callers and cookie-clearing handlers.
	if rt.ConsumedAt != nil {
		if time.Since(*rt.ConsumedAt) > s.reuseGrace {
			if rerr := s.store.RevokeFamily(ctx, rt.FamilyID, opts...); rerr != nil {
				return nil, fmt.Errorf("%w: family revocation failed: %v", tokens.ErrRefreshTokenReused, rerr)
			}
		}
		return nil, tokens.ErrRefreshTokenReused
	}

	if time.Now().After(rt.ExpiresAt) {
		return nil, tokens.ErrTokenExpired
	}

	// Atomically consume (single-use). Losing this race means another in-flight request
	// rotated the SAME not-yet-consumed token first. That is benign concurrency (parallel
	// tabs, link prefetch, concurrent sub-resource loads), NOT theft — so we reject this
	// request WITHOUT revoking the family. A genuine replay is still caught above on the
	// next presentation, once ConsumedAt has been set by the completed rotation.
	if err := s.store.ConsumeRefreshToken(ctx, hash, opts...); err != nil {
		return nil, err
	}

	// Resolve fresh claims (status, scopes, roles, ...) at rotation time rather than
	// trusting values frozen at login.
	claims, err := s.claimsProvider.ClaimsForUser(ctx, rt.UserID, rt.TenantID)
	if err != nil {
		return nil, err
	}

	// The tenant is immutable within a rotation family: keep the descendant in the SAME
	// partition used to find/consume/revoke, regardless of what the provider returns —
	// otherwise a divergent tenant would orphan the token out of reach of family
	// revocation. And the access-token lifetime is issuer-controlled on refresh: never
	// honor a provider-supplied expiry, which could extend a short-lived token unbounded.
	claims.TenantID = rt.TenantID
	claims.ExpiresAt = time.Time{}

	// Issue a new pair within the SAME family to preserve the rotation chain.
	return s.issuePair(ctx, claims, rt.FamilyID)
}

// IssueAPIKey generates a new API Key with the specified prefix and claims.
func (s *Service[C]) IssueAPIKey(ctx context.Context, prefix string, claims tokens.Claims[C]) (*tokens.APIKey[C], error) {
	keyBytes := make([]byte, s.apiKeyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	tokenStr := prefix + base64.RawURLEncoding.EncodeToString(keyBytes)

	// Hash the token for storage.
	hashStr := tokens.HashToken(tokenStr)

	var expiresAt *time.Time
	if !claims.ExpiresAt.IsZero() {
		expiresAt = &claims.ExpiresAt
	}

	key := &tokens.APIKey[C]{
		ID:        uuid.New(),
		TenantID:  claims.TenantID,
		Prefix:    prefix,
		Token:     tokenStr,
		Hash:      hashStr,
		ExpiresAt: expiresAt,
		Claims:    claims,
	}

	if err := s.store.SaveAPIKey(ctx, key, tokens.WithTenant(claims.TenantID)); err != nil {
		return nil, err
	}

	return key, nil
}

// VerifyAccessToken parses and validates an access token, returning its claims.
func (s *Service[C]) VerifyAccessToken(ctx context.Context, tokenStr string) (*tokens.Claims[C], error) {
	var wrapper claimsWrapper[C]

	token, err := jwt.ParseWithClaims(tokenStr, &wrapper, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, tokens.ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, tokens.ErrInvalidToken
	}

	subject, err := uuid.Parse(wrapper.Subject)
	if err != nil {
		return nil, tokens.ErrInvalidClaims
	}

	claims := tokens.Claims[C]{
		Subject:   subject,
		TenantID:  wrapper.TenantID,
		IssuedAt:  wrapper.IssuedAt.Time,
		ExpiresAt: wrapper.ExpiresAt.Time,
		Audiences: wrapper.Audience,
		Scopes:    wrapper.Scopes,
		Groups:    wrapper.Groups,
		Roles:     wrapper.Roles,
		AMR:       wrapper.AMR,
		Custom:    wrapper.Custom,
	}

	return &claims, nil
}

// VerifyRefreshToken validates a refresh token against the store and returns its claims.
func (s *Service[C]) VerifyRefreshToken(ctx context.Context, token string) (*tokens.Claims[C], error) {
	hash := tokens.HashToken(token)

	// Since we don't store full claims for refresh tokens in this simple Store,
	// we just verify existence and return a minimal Claims object with the Subject.
	rt, err := s.store.FindRefreshToken(ctx, hash)
	if err != nil {
		return nil, err
	}

	if rt.ConsumedAt != nil {
		return nil, tokens.ErrRefreshTokenReused
	}

	if time.Now().After(rt.ExpiresAt) {
		return nil, tokens.ErrTokenExpired
	}

	return &tokens.Claims[C]{
		Subject:   rt.UserID,
		TenantID:  rt.TenantID,
		ExpiresAt: rt.ExpiresAt,
	}, nil
}

// VerifyAPIKey validates an API key against the store and returns its claims.
func (s *Service[C]) VerifyAPIKey(ctx context.Context, key string) (*tokens.Claims[C], error) {
	hash := tokens.HashToken(key)

	apiKey, err := s.store.FindAPIKeyByHash(ctx, hash)
	if err != nil {
		return nil, err
	}

	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return nil, tokens.ErrTokenExpired
	}

	return &apiKey.Claims, nil
}

// Verify interface compliance.
var (
	_ tokens.Issuer[any]   = (*Service[any])(nil)
	_ tokens.Verifier[any] = (*Service[any])(nil)
	_ tokens.Rotator[any]  = (*Service[any])(nil)
)
