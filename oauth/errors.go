package oauth

import "errors"

var (
	// ErrExchangeFailed is returned when the authorization-code exchange with the provider's
	// token endpoint fails (network error, non-200 status, or an unusable token response).
	ErrExchangeFailed = errors.New("oauth: authorization code exchange failed")

	// ErrUserInfoFailed is returned when fetching the user profile from the provider fails.
	ErrUserInfoFailed = errors.New("oauth: fetching user info failed")
)

// Note: the callback handler signals state-mismatch, missing-code and missing-email failures
// directly as HTTP responses (or a ?error=<code> redirect), not as returned Go errors, so it
// exposes no sentinel for callers to errors.Is against. Previously declared ErrStateMismatch,
// ErrMissingCode and ErrEmailMissing sentinels were never returned anywhere and were removed
// rather than left as misleading dead exports (audit N6).
