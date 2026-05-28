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
	Custom   C        `json:"custom"`
}

// Service provides JWT-based implementations of tokens.Issuer and tokens.Verifier.
type Service[C any] struct {
	store         tokens.Store[C]
	secretKey     []byte
	issuer        string
	accessTTL     time.Duration
	refreshTTL    time.Duration
	refreshLength int
	apiKeyLength  int
}

// Config defines the configuration for the JWT Service.
type Config[C any] struct {
	Store         tokens.Store[C]
	SecretKey     string
	Issuer        string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	RefreshLength int
	APIKeyLength  int
}

// New creates a new JWT Service.
func New[C any](cfg Config[C]) *Service[C] {
	if cfg.RefreshLength == 0 {
		cfg.RefreshLength = 32
	}
	if cfg.APIKeyLength == 0 {
		cfg.APIKeyLength = 32
	}

	return &Service[C]{
		store:         cfg.Store,
		secretKey:     []byte(cfg.SecretKey),
		issuer:        cfg.Issuer,
		accessTTL:     cfg.AccessTTL,
		refreshTTL:    cfg.RefreshTTL,
		refreshLength: cfg.RefreshLength,
		apiKeyLength:  cfg.APIKeyLength,
	}
}

// IssueTokenPair generates a new Access and Refresh token pair for the given claims.
func (s *Service[C]) IssueTokenPair(ctx context.Context, claims tokens.Claims[C]) (*tokens.TokenPair[C], error) {
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
		Custom:   claims.Custom,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, wrapper)
	accessTokenStr, err := token.SignedString(s.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Generate opaque refresh token
	refreshBytes := make([]byte, s.refreshLength)
	if _, err := rand.Read(refreshBytes); err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshTokenStr := base64.RawURLEncoding.EncodeToString(refreshBytes)
	refreshHash := tokens.HashToken(refreshTokenStr)
	refreshExpiresAt := now.Add(s.refreshTTL)

	return &tokens.TokenPair[C]{
		AccessToken:           accessTokenStr,
		RefreshToken:          refreshTokenStr,
		RefreshTokenHash:      refreshHash,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
		Claims:                claims,
	}, s.store.SaveRefreshToken(ctx, refreshHash, claims.Subject, refreshExpiresAt, tokens.WithTenant(claims.TenantID))
	}

	// IssueAPIKey generates a new API Key with the specified prefix and claims.
	func (s *Service[C]) IssueAPIKey(ctx context.Context, prefix string, claims tokens.Claims[C]) (*tokens.APIKey[C], error) {
	keyBytes := make([]byte, s.apiKeyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate api key: %w", err)
	}

	tokenStr := prefix + base64.RawURLEncoding.EncodeToString(keyBytes)

	// Hash the token for storage
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
		Roles:    wrapper.Roles,
		Custom:    wrapper.Custom,
	}

	return &claims, nil
	}

// VerifyRefreshToken validates a refresh token against the store and returns its claims.
func (s *Service[C]) VerifyRefreshToken(ctx context.Context, token string) (*tokens.Claims[C], error) {
	hash := tokens.HashToken(token)

	// Since we don't store full claims for refresh tokens in this simple Store,
	// we just verify existence and return a minimal Claims object with the Subject.
	userID, expiresAt, err := s.store.FindRefreshTokenByHash(ctx, hash)
	if err != nil {
		return nil, err
	}

	if time.Now().After(expiresAt) {
		return nil, tokens.ErrTokenExpired
	}

	return &tokens.Claims[C]{
		Subject:   userID,
		ExpiresAt: expiresAt,
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


// Verify interface compliance
var _ tokens.Issuer[any] = (*Service[any])(nil)
var _ tokens.Verifier[any] = (*Service[any])(nil)
