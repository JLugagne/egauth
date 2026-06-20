package jwt

import (
	"context"

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
func (s *SingleTenant[C]) VerifyAPIKey(ctx context.Context, key string) (*tokens.Claims[C], error) {
	return s.svc.VerifyAPIKey(ctx, "", key)
}

// Rotate calls Service.Rotate on the empty tenant.
func (s *SingleTenant[C]) Rotate(ctx context.Context, refreshToken string) (*tokens.TokenPair[C], error) {
	return s.svc.Rotate(ctx, "", refreshToken)
}

// VerifyAccessTokenForTenant calls Service.VerifyAccessTokenForTenant.
func (s *SingleTenant[C]) VerifyAccessTokenForTenant(ctx context.Context, tenantID string, tokenStr string) (*tokens.Claims[C], error) {
	return s.svc.VerifyAccessTokenForTenant(ctx, tenantID, tokenStr)
}
