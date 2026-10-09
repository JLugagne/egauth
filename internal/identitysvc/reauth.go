package identitysvc

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store"
)

// CheckPassword verifies password for the session subject sub, for /reauth. It shares the login's
// lockout: a wrong password is charged, a locked account is refused even with the right one, and a
// success clears the failure count. An account without a password hashes a decoy and is refused, so
// the check never passes without a stored hash. It returns ErrInvalidCredentials, or an error joined
// with httpx.ErrServiceUnavailable on store failure.
func (s *Service) CheckPassword(ctx context.Context, sub core.Subject, password string) error {
	cred, err := s.identity.GetPassword(ctx, sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.decoy(ctx, password)
		return ErrInvalidCredentials
	case err != nil:
		s.decoy(ctx, password)
		return errors.Join(httpx.ErrServiceUnavailable, err)
	}
	ok := s.matches(ctx, cred.PHC.PHC(), password)
	if cred.LockedUntil.After(s.clock.Now()) {
		return ErrInvalidCredentials
	}
	if !ok {
		s.recordFailure(ctx, sub)
		return ErrInvalidCredentials
	}
	if cred.FailedAttempts > 0 {
		if err := s.identity.ResetPasswordFailures(ctx, sub); err != nil {
			return errors.Join(httpx.ErrServiceUnavailable, err)
		}
	}
	return nil
}
