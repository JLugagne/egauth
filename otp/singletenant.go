package otp

import (
	"context"

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

// Issue calls Service.Issue on the empty tenant.
func (s *SingleTenant) Issue(ctx context.Context, subjectID uuid.UUID, purpose string) (*Challenge, error) {
	return s.svc.Issue(ctx, "", subjectID, purpose)
}

// Verify calls Service.Verify on the empty tenant.
func (s *SingleTenant) Verify(ctx context.Context, subjectID uuid.UUID, purpose, code string) error {
	return s.svc.Verify(ctx, "", subjectID, purpose, code)
}

// Invalidate calls Service.Invalidate on the empty tenant.
func (s *SingleTenant) Invalidate(ctx context.Context, subjectID uuid.UUID, purpose string) error {
	return s.svc.Invalidate(ctx, "", subjectID, purpose)
}
