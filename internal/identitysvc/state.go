package identitysvc

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

// AccountState returns the authoritative state of sub for admission, reauthentication and renewal.
// It is the only producer of core.AccountState (G6). An unknown subject yields the zero state, which
// every transition refuses; any other store failure is joined with httpx.ErrUnavailable so that the
// caller answers 503 and never treats an outage as a refusal or an admission.
func (s *Service) AccountState(ctx context.Context, sub core.Subject) (core.AccountState, error) {
	u, err := s.identity.GetUser(ctx, sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return core.AccountState{}, nil
	case err != nil:
		return core.AccountState{}, errors.Join(httpx.ErrUnavailable, err)
	}
	return stateOf(u), nil
}

func stateOf(u identity.User) core.AccountState {
	return core.NewAccountState(true, !u.DisabledAt.IsZero(), !u.DeletedAt.IsZero(), u.MustChange, !u.EmailVerifiedAt.IsZero(), u.SecurityEpoch)
}
