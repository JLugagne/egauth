package tokens

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// NewAccountRevoker returns a cross-module revocation hook that invalidates the user's STORED
// credentials in this tokens store. Precisely, it does two things and nothing else:
//
//   - RevokeAllRefreshTokensForUser: every refresh token of the user, across every rotation
//     family, becomes unusable — so no further rotation can mint a new pair and the user's
//     sessions cannot be renewed past the current access token.
//   - RevokeAllAPIKeysForUser: every API key the user issued is soft-revoked (RevokedAt stamped),
//     so key verification fails from the next request on.
//
// What SURVIVES it, and for how long:
//
//   - Already-issued ACCESS tokens. They are stateless signed JWTs that this package does not
//     consult a store to verify, so an access token stays valid until it expires — at most
//     jwt.Config.AccessTTL after issuance (15 minutes with the webapp preset's default). Bound
//     that window with a short AccessTTL; there is no way to retract an access token in flight.
//   - Sessions in the sessions module (a separate store this hook cannot reach). Revoke those with
//     sessions.Service.RevokeAllForUser, registered as an additional hook.
//   - Enrollment data (MFA secrets, passkeys), deliberately: a disable is reversible and the
//     account must work again after EnableUser.
//
// The returned function has the signature expected by identity.WithDisableRevokers and
// identity.WithAccountErasers, so wiring it makes identity.DisableUser — or DeleteAccount —
// cascade into the tokens module without coupling the two packages directly:
//
//	revoker := tokens.NewAccountRevoker(tokenStore)
//	svc := identity.NewService(store, hasher, policy, identity.WithDisableRevokers(revoker))
//
// Revoking stored credentials is only half of ending access: refresh-token ROTATION must also
// re-check account status, or a refresh token issued before the disable but not yet revoked (a
// concurrent request, a retried disable) rotates into a fresh pair. Wrap the issuer's
// ClaimsProvider with identity.ActiveClaimsProvider — the webapp preset wires both halves.
//
// Both revocations run even if the first errors; their errors are joined so one failure never
// masks the other. The hook is idempotent — a user with no tokens or keys is a no-op returning
// nil — so it is safe to retry, which matters because disable/delete may be re-attempted.
func NewAccountRevoker[C any](store Store[C]) func(ctx context.Context, tenantID string, userID uuid.UUID) error {
	return func(ctx context.Context, tenantID string, userID uuid.UUID) error {
		var errs []error
		if err := store.RevokeAllRefreshTokensForUser(ctx, tenantID, userID); err != nil {
			errs = append(errs, err)
		}
		if err := store.RevokeAllAPIKeysForUser(ctx, tenantID, userID); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
}
