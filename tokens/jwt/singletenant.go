package jwt

import (
	"context"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
)

// SingleTenant is a convenience wrapper around *Service[C] for applications that run with
// exactly ONE tenant. It exposes every Service method, dropping the tenantID argument from
// the ones that take it (Rotate) and delegating with the empty tenant ("") — the
// single-tenant default partition. The Issue*/Verify* methods are passed through unchanged
// (they carry the tenant on Claims.TenantID, which a single-tenant app simply leaves empty).
//
// SECURITY: use this ONLY in genuinely single-tenant deployments. Rotate is hard-wired to
// the empty tenant, so it can never rotate another tenant's refresh-token family; it must
// NOT be mixed with multi-tenant calls against the same Service. In a multi-tenant
// application, call Service directly and pass the resolved tenant explicitly so every
// operation is scoped — that explicit tenant boundary is what prevents IDOR / cross-tenant
// access.
type SingleTenant[C any] struct {
	svc *Service[C]
}

// NewSingleTenant wraps svc so Rotate can be called without a tenantID (it uses the empty
// tenant ""). See SingleTenant for the single-tenant-only contract.
func NewSingleTenant[C any](svc *Service[C]) *SingleTenant[C] {
	return &SingleTenant[C]{svc: svc}
}

// Service returns the underlying tenant-aware Service, for the occasional call that needs an
// explicit tenant.
func (s *SingleTenant[C]) Service() *Service[C] { return s.svc }

// IssueTokenPair calls Service.IssueTokenPair (tenant, if any, is carried on claims).
func (s *SingleTenant[C]) IssueTokenPair(ctx context.Context, claims tokens.Claims[C]) (*tokens.TokenPair[C], error) {
	return s.svc.IssueTokenPair(ctx, claims)
}

// IssueAccessToken calls Service.IssueAccessToken (tenant, if any, is carried on claims). It mints a
// STANDALONE access token: no refresh token and no persisted refresh family.
func (s *SingleTenant[C]) IssueAccessToken(ctx context.Context, claims tokens.Claims[C]) (string, time.Time, error) {
	return s.svc.IssueAccessToken(ctx, claims)
}

// IssueAPIKey calls Service.IssueAPIKey (tenant, if any, is carried on claims).
func (s *SingleTenant[C]) IssueAPIKey(ctx context.Context, prefix string, keyType tokens.KeyType, createdBy uuid.UUID, claims tokens.Claims[C]) (*tokens.APIKey[C], error) {
	return s.svc.IssueAPIKey(ctx, prefix, keyType, createdBy, claims)
}

// VerifyRefreshToken calls Service.VerifyRefreshToken on the empty tenant. Its signature
// keeps the single-tenant convenience contract (no tenantID): the underlying lookup is
// scoped to the default partition ("").
func (s *SingleTenant[C]) VerifyRefreshToken(ctx context.Context, token string) (*tokens.Claims[C], error) {
	return s.svc.VerifyRefreshToken(ctx, "", token)
}

// VerifyAPIKey calls Service.VerifyAPIKey on the empty tenant. Its signature keeps the
// single-tenant convenience contract (no tenantID): the underlying lookup is scoped to the
// default partition ("").
func (s *SingleTenant[C]) VerifyAPIKey(ctx context.Context, key string, rc ...event.RequestContext) (*tokens.Claims[C], error) {
	return s.svc.VerifyAPIKey(ctx, "", key, rc...)
}

// VerifyAPIKeyActor calls Service.VerifyAPIKeyActor on the empty tenant, returning the
// classified egauth.Actor alongside the claims. Like VerifyAPIKey it drops the tenantID
// (the lookup is scoped to the default partition "").
func (s *SingleTenant[C]) VerifyAPIKeyActor(ctx context.Context, key string, rc ...event.RequestContext) (egauth.Actor, *tokens.Claims[C], error) {
	return s.svc.VerifyAPIKeyActor(ctx, "", key, rc...)
}

// Rotate calls Service.Rotate on the empty tenant.
func (s *SingleTenant[C]) Rotate(ctx context.Context, refreshToken string) (*tokens.TokenPair[C], error) {
	return s.svc.Rotate(ctx, "", refreshToken)
}

// VerifyAccessTokenForTenant calls Service.VerifyAccessTokenForTenant.
func (s *SingleTenant[C]) VerifyAccessTokenForTenant(ctx context.Context, tenantID string, tokenStr string) (*tokens.Claims[C], error) {
	return s.svc.VerifyAccessTokenForTenant(ctx, tenantID, tokenStr)
}

// DeleteExpired calls Service.DeleteExpired on the empty tenant (the single-tenant default
// partition) and emits api_key.purged with the deleted count. See Service.DeleteExpired for
// the event contract.
func (s *SingleTenant[C]) DeleteExpired(ctx context.Context) (int64, error) {
	return s.svc.DeleteExpired(ctx, "")
}

// RevokeAPIKey calls Service.RevokeAPIKey on the empty tenant (the single-tenant default
// partition). Its signature keeps the single-tenant convenience contract (no tenantID): the
// underlying revoke is scoped to the default partition (""). See Service.RevokeAPIKey for the
// error/no-op and audit-event contract.
func (s *SingleTenant[C]) RevokeAPIKey(ctx context.Context, keyID uuid.UUID) error {
	return s.svc.RevokeAPIKey(ctx, "", keyID)
}

// ListAPIKeysByCreator calls Service.ListAPIKeysByCreator on the empty tenant (the single-tenant
// default partition). Its signature keeps the single-tenant convenience contract (no tenantID):
// the underlying listing is scoped to the default partition (""). See Service.ListAPIKeysByCreator
// for the returned-key contract.
func (s *SingleTenant[C]) ListAPIKeysByCreator(ctx context.Context, createdBy uuid.UUID) ([]*tokens.APIKey[C], error) {
	return s.svc.ListAPIKeysByCreator(ctx, "", createdBy)
}
