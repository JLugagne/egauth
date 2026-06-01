package mfa

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

// EnrollTOTP calls Service.EnrollTOTP on the empty tenant.
func (s *SingleTenant) EnrollTOTP(ctx context.Context, userID uuid.UUID, account string) (*Enrollment, error) {
	return s.svc.EnrollTOTP(ctx, "", userID, account)
}

// ConfirmTOTP calls Service.ConfirmTOTP on the empty tenant.
func (s *SingleTenant) ConfirmTOTP(ctx context.Context, userID uuid.UUID, code string) ([]string, error) {
	return s.svc.ConfirmTOTP(ctx, "", userID, code)
}

// VerifyTOTP calls Service.VerifyTOTP on the empty tenant.
func (s *SingleTenant) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) error {
	return s.svc.VerifyTOTP(ctx, "", userID, code)
}

// VerifyRecoveryCode calls Service.VerifyRecoveryCode on the empty tenant.
func (s *SingleTenant) VerifyRecoveryCode(ctx context.Context, userID uuid.UUID, code string) error {
	return s.svc.VerifyRecoveryCode(ctx, "", userID, code)
}

// RegenerateRecoveryCodes calls Service.RegenerateRecoveryCodes on the empty tenant.
func (s *SingleTenant) RegenerateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.svc.RegenerateRecoveryCodes(ctx, "", userID)
}

// DisableTOTP calls Service.DisableTOTP on the empty tenant.
func (s *SingleTenant) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	return s.svc.DisableTOTP(ctx, "", userID)
}

// IsEnrolled calls Service.IsEnrolled on the empty tenant.
func (s *SingleTenant) IsEnrolled(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.svc.IsEnrolled(ctx, "", userID)
}
