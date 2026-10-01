package tokens

import (
	"errors"
	"net/http"
)

// ErrInterimDenied is returned by DenyInterim when the request's verified access token
// was minted before a second factor was presented (Claims.Interim). It is an exported
// sentinel so enrollment handlers can map the refusal onto their own error/response shape
// with errors.Is while sharing one gate implementation.
var ErrInterimDenied = errors.New("tokens: interim access token presented; a completed second factor is required")

// DenyInterim is a ready-made, non-generic gate for credential-enrollment handlers
// (passkey, mfa, identity) whose signatures take a func(*http.Request) error rather than
// an AuthOption[C]. It returns ErrInterimDenied when the request context carries an
// interim (pre-second-factor) access-token claims — as recorded by RequireAuth and
// ContextMiddleware from the verified Claims — and nil otherwise, including when no token
// context is present at all.
//
// This is the structural half of the step-up contract: WithDenyInterim asks "is this
// credential known to be incomplete?" at the middleware layer, and DenyInterim exposes
// the same answer to handlers that gate an enrollment action themselves, without leaking
// the generic Claims[C] type into their signatures. WithDenyInterim behavior is unchanged.
func DenyInterim(r *http.Request) error {
	if r == nil {
		return nil
	}
	if interim, _ := r.Context().Value(interimContextKey{}).(bool); interim {
		return ErrInterimDenied
	}
	return nil
}
