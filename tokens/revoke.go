package tokens

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// NewAccountRevoker returns a cross-module revocation hook that invalidates EVERY token a user
// holds: it revokes all of the user's refresh tokens (killing every active session) and
// soft-revokes every API key the user issued. The returned function has the signature expected by
// identity.WithDisableRevokers (and identity.WithAccountErasers), so wiring it makes
// identity.DisableUser — or DeleteAccount — cascade into the tokens module without coupling the
// two packages directly:
//
//	revoker := tokens.NewAccountRevoker(tokenStore)
//	svc := identity.NewService(store, hasher, policy, identity.WithDisableRevokers(revoker))
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
