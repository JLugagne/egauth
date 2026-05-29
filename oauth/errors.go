package oauth

import "errors"

var (
	// ErrExchangeFailed is returned when the authorization-code exchange with the provider's
	// token endpoint fails (network error, non-200 status, or an unusable token response).
	ErrExchangeFailed = errors.New("oauth: authorization code exchange failed")

	// ErrUserInfoFailed is returned when fetching the user profile from the provider fails.
	ErrUserInfoFailed = errors.New("oauth: fetching user info failed")

	// ErrStateMismatch is returned when the state echoed back by the provider does not match
	// the value stored in the state cookie (possible CSRF) or the cookie is absent.
	ErrStateMismatch = errors.New("oauth: state mismatch")

	// ErrMissingCode is returned when the provider redirect carries no authorization code.
	ErrMissingCode = errors.New("oauth: missing authorization code")

	// ErrEmailMissing is returned when the provider returns no email, which is required to
	// provision or resolve an account.
	ErrEmailMissing = errors.New("oauth: provider returned no email")
)
