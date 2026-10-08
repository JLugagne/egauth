package egauth

import "errors"

// ConfigError is one configuration problem found by New. Field is the dotted path of the offending
// field, with [i] for slice elements (for example "Modules.APIKeys.Kinds[0]"). New returns every
// problem at once as an errors.Join of *ConfigError; use errors.As to read the first one.
type ConfigError struct {
	Field   string
	Problem string
}

func (e *ConfigError) Error() string {
	if e.Field == "" {
		return "egauth: configuration: " + e.Problem
	}
	return "egauth: configuration: " + e.Field + ": " + e.Problem
}

var (
	// ErrClosed is returned by Ready after Close.
	ErrClosed = errors.New("egauth: closed")
	// ErrForbidden is returned by a facade when the caller may not act on the target.
	ErrForbidden = errors.New("egauth: forbidden")
	// ErrReauthRequired is returned by a facade when the caller's session is not fresh within
	// SessionPolicy.ReauthWindow or lacks the second factor its subject enrolled.
	ErrReauthRequired = errors.New("egauth: reauthentication required")
	// ErrAPIKeyCaller is returned by every facade method for an API-key caller.
	ErrAPIKeyCaller = errors.New("egauth: API-key callers cannot use this method")
	// ErrSystemCallerInRequest is returned by every facade method for a System caller used while
	// serving a request.
	ErrSystemCallerInRequest = errors.New("egauth: system caller used inside a request")
	// ErrTenantMismatch is returned when a session caller targets another tenant.
	ErrTenantMismatch = errors.New("egauth: tenant mismatch")
	// ErrClaimsNotSubset is returned by APIKeys.Create when the requested roles, scopes or groups
	// exceed the caller's current claims.
	ErrClaimsNotSubset = errors.New("egauth: requested claims exceed the caller's")
)
