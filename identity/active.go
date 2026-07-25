package identity

import (
	"context"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/tokens"
)

// ActiveChecker reports whether an account may still act. The Service returned by NewService
// implements it (see Service.EnsureActive); it is broken out so ActiveClaimsProvider can be wired
// from a narrower dependency than the whole Service.
type ActiveChecker interface {
	// EnsureActive returns nil for a live account, ErrAccountDisabled for a suspended one and
	// ErrUserNotFound for an unknown, soft-deleted or cross-tenant one.
	EnsureActive(ctx context.Context, tenantID string, userID uuid.UUID) error
}

// ActiveClaimsProvider wraps next with the account-status re-check that refresh-token rotation
// owes the account lifecycle. Rotation resolves fresh claims through a tokens.ClaimsProvider, and
// that provider is the ONLY place a rotation can be refused: an issuer whose provider always
// succeeds keeps renewing a suspended or deleted user's session — and each rotation pushes the
// refresh expiry out again, so access is not merely retained but extended indefinitely, defeating
// offboarding, erasure requests and compromise response.
//
// The wrapper calls checker.EnsureActive first and returns its error verbatim
// (ErrAccountDisabled / ErrUserNotFound), which aborts Rotate before a new pair is minted; the
// presented refresh token stays unconsumed and the shipped tokens.RefreshHandler answers 401 and
// clears the auth cookies. Only for a live account does it delegate to next.
//
// Wire it around whatever provider carries your custom claims:
//
//	issuer := jwt.New[AppClaims](jwt.Config[AppClaims]{
//		// ...
//		ClaimsProvider: identity.ActiveClaimsProvider(svc, myProvider),
//	})
//
// It panics on a nil checker or provider, so a mis-wired composition root fails at startup rather
// than serving refreshes that silently skip the status check.
func ActiveClaimsProvider[C any](checker ActiveChecker, next tokens.ClaimsProvider[C]) tokens.ClaimsProvider[C] {
	if checker == nil {
		panic("identity: ActiveClaimsProvider requires a non-nil ActiveChecker")
	}
	if next == nil {
		panic("identity: ActiveClaimsProvider requires a non-nil ClaimsProvider")
	}
	return tokens.ClaimsProviderFunc[C](func(ctx context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[C], error) {
		if err := checker.EnsureActive(ctx, tenantID, userID); err != nil {
			var zero tokens.Claims[C]
			return zero, err
		}
		return next.ClaimsForUser(ctx, userID, tenantID)
	})
}
