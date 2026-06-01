package identity

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
// to the empty tenant, so it can never read or write another tenant's data; conversely, it
// must NOT be mixed with multi-tenant calls against the same Service (a row written through
// SingleTenant lives in tenant "" and is invisible to a tenant-"acme" lookup, and vice
// versa). In a multi-tenant application, call Service directly and pass the resolved tenant
// explicitly so every operation is scoped — that explicit tenant boundary is what prevents
// IDOR / cross-tenant access.
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

// Register calls Service.Register on the empty tenant.
func (s *SingleTenant) Register(ctx context.Context, email, password string) (*User, error) {
	return s.svc.Register(ctx, "", email, password)
}

// Authenticate calls Service.Authenticate on the empty tenant.
func (s *SingleTenant) Authenticate(ctx context.Context, provider, providerID, password string) (*User, error) {
	return s.svc.Authenticate(ctx, "", provider, providerID, password)
}

// RequestPasswordReset calls Service.RequestPasswordReset on the empty tenant.
func (s *SingleTenant) RequestPasswordReset(ctx context.Context, email string) (token string, user *User, err error) {
	return s.svc.RequestPasswordReset(ctx, "", email)
}

// ResetPassword calls Service.ResetPassword on the empty tenant.
func (s *SingleTenant) ResetPassword(ctx context.Context, token, newPassword string) error {
	return s.svc.ResetPassword(ctx, "", token, newPassword)
}

// RequestEmailVerification calls Service.RequestEmailVerification on the empty tenant.
func (s *SingleTenant) RequestEmailVerification(ctx context.Context, userID uuid.UUID) (token string, err error) {
	return s.svc.RequestEmailVerification(ctx, "", userID)
}

// VerifyEmail calls Service.VerifyEmail on the empty tenant.
func (s *SingleTenant) VerifyEmail(ctx context.Context, token string) (*User, error) {
	return s.svc.VerifyEmail(ctx, "", token)
}

// LinkOrCreateIdentity calls Service.LinkOrCreateIdentity on the empty tenant.
func (s *SingleTenant) LinkOrCreateIdentity(ctx context.Context, provider, providerID, email string, emailVerified bool) (*User, error) {
	return s.svc.LinkOrCreateIdentity(ctx, "", provider, providerID, email, emailVerified)
}

// RequestMagicLink calls Service.RequestMagicLink on the empty tenant.
func (s *SingleTenant) RequestMagicLink(ctx context.Context, email string) (token string, user *User, err error) {
	return s.svc.RequestMagicLink(ctx, "", email)
}

// LoginWithMagicLink calls Service.LoginWithMagicLink on the empty tenant.
func (s *SingleTenant) LoginWithMagicLink(ctx context.Context, token string) (*User, error) {
	return s.svc.LoginWithMagicLink(ctx, "", token)
}

// ChangePassword calls Service.ChangePassword on the empty tenant.
func (s *SingleTenant) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	return s.svc.ChangePassword(ctx, "", userID, currentPassword, newPassword)
}

// RequestEmailChange calls Service.RequestEmailChange on the empty tenant.
func (s *SingleTenant) RequestEmailChange(ctx context.Context, userID uuid.UUID, newEmail string) (token string, err error) {
	return s.svc.RequestEmailChange(ctx, "", userID, newEmail)
}

// ConfirmEmailChange calls Service.ConfirmEmailChange on the empty tenant.
func (s *SingleTenant) ConfirmEmailChange(ctx context.Context, token string) (*User, error) {
	return s.svc.ConfirmEmailChange(ctx, "", token)
}

// DeleteAccount calls Service.DeleteAccount on the empty tenant.
func (s *SingleTenant) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	return s.svc.DeleteAccount(ctx, "", userID)
}
