package sessions

import (
	"context"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/google/uuid"
)

// SingleTenant is a convenience wrapper around Service for applications that run with
// exactly ONE tenant. It exposes every Service method WITHOUT the tenantID argument,
// delegating each call to the underlying Service with the empty tenant ("") — the
// single-tenant default partition.
//
// SECURITY: use this ONLY in genuinely single-tenant deployments. Every call is hard-wired
// to the empty tenant, so it can never read or write another tenant's data; it must NOT be
// mixed with multi-tenant calls against the same Service. In a multi-tenant application,
// call Service directly and pass the resolved tenant explicitly so every operation is
// scoped — that explicit tenant boundary is what prevents IDOR / cross-tenant access.
type SingleTenant struct {
	svc Service
}

// NewSingleTenant wraps svc so its methods can be called without a tenantID; every call uses
// the empty tenant (""). See SingleTenant for the single-tenant-only contract.
func NewSingleTenant(svc Service) *SingleTenant {
	return &SingleTenant{svc: svc}
}

// Service returns the underlying tenant-aware Service, for the occasional call that needs an
// explicit tenant.
func (s *SingleTenant) Service() Service { return s.svc }

// CreateSession calls Service.CreateSession on the empty tenant.
func (s *SingleTenant) CreateSession(ctx context.Context, userID uuid.UUID, userAgent string, ip string, duration time.Duration) (*Session, string, error) {
	return s.svc.CreateSession(ctx, "", userID, userAgent, ip, duration)
}

// ValidateSession calls Service.ValidateSession on the empty tenant.
func (s *SingleTenant) ValidateSession(ctx context.Context, token string) (*Session, error) {
	return s.svc.ValidateSession(ctx, "", token)
}

// Touch calls Service.Touch on the empty tenant.
func (s *SingleTenant) Touch(ctx context.Context, token string, duration time.Duration) (*Session, error) {
	return s.svc.Touch(ctx, "", token, duration)
}

// Rotate calls Service.Rotate on the empty tenant.
func (s *SingleTenant) Rotate(ctx context.Context, token string, duration time.Duration) (*Session, string, error) {
	return s.svc.Rotate(ctx, "", token, duration)
}

// BindUser calls Service.BindUser on the empty tenant.
func (s *SingleTenant) BindUser(ctx context.Context, token string, userID uuid.UUID, duration time.Duration) (*Session, string, error) {
	return s.svc.BindUser(ctx, "", token, userID, duration)
}

// RevokeSession calls Service.RevokeSession on the empty tenant.
func (s *SingleTenant) RevokeSession(ctx context.Context, token string, rc ...event.RequestContext) error {
	return s.svc.RevokeSession(ctx, "", token, rc...)
}

// RevokeAllForUser calls Service.RevokeAllForUser on the empty tenant.
func (s *SingleTenant) RevokeAllForUser(ctx context.Context, userID uuid.UUID, rc ...event.RequestContext) error {
	return s.svc.RevokeAllForUser(ctx, "", userID, rc...)
}
