package identitysvc

import (
	"context"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/store/identity"
)

// The problems the password endpoints answer besides those of httpx.
var (
	ErrInvalidCredentials = httpx.NewProblem(http.StatusUnauthorized, "invalid_credentials")
	ErrInvalidIdentifier  = httpx.NewProblem(http.StatusBadRequest, "invalid_identifier")
	ErrInvalidToken       = httpx.NewProblem(http.StatusBadRequest, "invalid_token")
	ErrAccountExists      = httpx.NewProblem(http.StatusConflict, "account_exists")
	ErrPasswordTooShort   = httpx.NewProblem(http.StatusBadRequest, "password_too_short")
	ErrPasswordTooLong    = httpx.NewProblem(http.StatusBadRequest, "password_too_long")
	ErrPasswordBreached   = httpx.NewProblem(http.StatusBadRequest, "password_breached")
	ErrPasswordRejected   = httpx.NewProblem(http.StatusBadRequest, "password_rejected")
)

// AcceptPassword runs the library floor, then the breach check, then the configured Policy, and
// returns the hash of the NFKC form to store. A breach lookup that fails is answered 503: the check
// fails closed. Policy can only refuse what the floor accepted, never accept what it refused.
func (s *Service) AcceptPassword(ctx context.Context, password string) (identity.PasswordHash, error) {
	canon, err := passwords.Floor(password)
	if err != nil {
		return identity.PasswordHash{}, passwordProblem(err)
	}
	if s.breach != nil {
		breached, err := s.breach.IsBreached(ctx, canon)
		if err != nil {
			return identity.PasswordHash{}, errors.Join(httpx.ErrServiceUnavailable, err)
		}
		if breached {
			return identity.PasswordHash{}, ErrPasswordBreached
		}
	}
	if err := s.policy.Verify(ctx, canon); err != nil {
		return identity.PasswordHash{}, passwordProblem(err)
	}
	phc, err := s.hasher.Hash(ctx, canon)
	if err != nil {
		return identity.PasswordHash{}, errors.Join(httpx.ErrInternal, err)
	}
	if phc == "" || len(phc) > identity.MaxPHCLen {
		return identity.PasswordHash{}, httpx.ErrInternal
	}
	return identity.NewPasswordHash(phc), nil
}

func passwordProblem(err error) error {
	switch {
	case errors.Is(err, passwords.ErrPasswordTooShort):
		return errors.Join(ErrPasswordTooShort, err)
	case errors.Is(err, passwords.ErrPasswordTooLong):
		return errors.Join(ErrPasswordTooLong, err)
	case errors.Is(err, passwords.ErrPasswordBreached):
		return errors.Join(ErrPasswordBreached, err)
	}
	return errors.Join(ErrPasswordRejected, err)
}

func (s *Service) matches(ctx context.Context, phc, password string) (bool, error) {
	canon := passwords.Canonical(password)
	err := s.hasher.Compare(ctx, passwords.PHC(phc), canon)
	ok := err == nil
	if canon != password {
		legacy := s.hasher.Compare(ctx, passwords.PHC(phc), password)
		ok = ok || legacy == nil
		err = errors.Join(err, legacy)
	}
	if !ok && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return false, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	return ok, nil
}

func (s *Service) decoy(ctx context.Context, password string) error {
	_, err := s.matches(ctx, s.decoyPHC, password)
	return err
}
