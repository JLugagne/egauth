// Package identity is egauth's account and credential-verification module: registration,
// password login (Authenticate), password reset, email verification, magic-link login,
// authenticated change-password / change-email, account deletion, and just-in-time
// provisioning of external (OAuth) identities.
//
// # Composable by design
//
// egauth is a set of independent modules in the style of the standard library's database/sql:
// you import the ones you need and wire them together with dependency injection, rather than
// adopting a framework that owns your HTTP router, ORM, and conventions. identity verifies
// credentials and manages the account lifecycle; it does NOT issue tokens or sessions — pair it
// with the tokens module (stateless JWT access + refresh rotation) or the sessions module
// (server-side sessions), whichever your application prefers. Password hashing and policy are
// themselves seams (the passwords module): identity takes a passwords.Hasher and passwords.Policy
// so you choose argon2 (the shipped reference) or your own.
//
// Multi-tenancy is explicit: every Service method takes a tenantID string (an empty string is the
// valid single-tenant default partition). In a genuinely single-tenant application, wrap the
// Service in a SingleTenant facade (NewSingleTenant) to drop the argument from every call.
//
// # Wiring
//
//	store := memory.NewStore()                         // identity/memory; or identity/pgx.NewStore(pool)
//	svc := identity.NewService(store, argon2.NewHasher(), policy.NewDefaultPolicy())
//	user, err := svc.Register(ctx, tenantID, email, password)
//
// NewService panics on a nil Store (fail-fast at startup); the hasher and policy may be nil for an
// OAuth-only deployment that runs no password flows.
//
// # HTTP handlers
//
// The module ships à-la-carte http.HandlerFunc factories — LoginHandler, RegisterHandler,
// RequestPasswordResetHandler, ResetPasswordHandler, VerifyEmailHandler, MagicLinkLoginHandler,
// ChangePasswordHandler, the change-email pair, DeleteAccountHandler — that you mount on your own
// mux. The login-style handlers take a tokens.Issuer and a ClaimsBuilder so the same flow works
// with any token backend. See the package examples for a complete login + refresh wiring.
//
// # Security posture
//
// Enumeration-safe by default (uniform responses and decoy hashing on unknown accounts),
// brute-force lockout, single-use selector/verifier tokens, email normalization, and a pre-auth
// body cap against hashing-DoS. See SECURITY.md for the full model.
package identity
