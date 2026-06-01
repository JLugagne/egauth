package passkey

import (
	"context"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// SingleTenant is a convenience wrapper around *Service for applications that run with
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
	svc *Service
}

// NewSingleTenant wraps svc so its methods can be called without a tenantID; every call uses
// the empty tenant (""). See SingleTenant for the single-tenant-only contract.
func NewSingleTenant(svc *Service) *SingleTenant {
	return &SingleTenant{svc: svc}
}

// Service returns the underlying tenant-aware Service, for the occasional call that needs an
// explicit tenant.
func (s *SingleTenant) Service() *Service { return s.svc }

// BeginRegistration calls Service.BeginRegistration on the empty tenant.
func (s *SingleTenant) BeginRegistration(ctx context.Context, userID uuid.UUID, name, displayName string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return s.svc.BeginRegistration(ctx, "", userID, name, displayName)
}

// FinishRegistration calls Service.FinishRegistration on the empty tenant.
func (s *SingleTenant) FinishRegistration(ctx context.Context, userID uuid.UUID, name, displayName string, session webauthn.SessionData, r *http.Request) (*Credential, error) {
	return s.svc.FinishRegistration(ctx, "", userID, name, displayName, session, r)
}

// BeginLogin calls Service.BeginLogin on the empty tenant.
func (s *SingleTenant) BeginLogin(ctx context.Context, userID uuid.UUID) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return s.svc.BeginLogin(ctx, "", userID)
}

// FinishLogin calls Service.FinishLogin on the empty tenant.
func (s *SingleTenant) FinishLogin(ctx context.Context, userID uuid.UUID, session webauthn.SessionData, r *http.Request) (*Credential, error) {
	return s.svc.FinishLogin(ctx, "", userID, session, r)
}

// BeginDiscoverableLogin calls Service.BeginDiscoverableLogin (no tenant scoping needed: it
// only builds an assertion challenge and touches no stored data).
func (s *SingleTenant) BeginDiscoverableLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return s.svc.BeginDiscoverableLogin()
}

// FinishDiscoverableLogin calls Service.FinishDiscoverableLogin on the empty tenant.
func (s *SingleTenant) FinishDiscoverableLogin(ctx context.Context, session webauthn.SessionData, r *http.Request) (*Credential, uuid.UUID, error) {
	return s.svc.FinishDiscoverableLogin(ctx, "", session, r)
}

// ListCredentials calls Service.ListCredentials on the empty tenant.
func (s *SingleTenant) ListCredentials(ctx context.Context, userID uuid.UUID) ([]*Credential, error) {
	return s.svc.ListCredentials(ctx, "", userID)
}

// DeleteCredential calls Service.DeleteCredential on the empty tenant.
func (s *SingleTenant) DeleteCredential(ctx context.Context, userID uuid.UUID, credentialID []byte) error {
	return s.svc.DeleteCredential(ctx, "", userID, credentialID)
}
