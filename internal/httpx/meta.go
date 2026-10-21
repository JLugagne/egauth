// Package httpx is the request edge of every auth endpoint (DESIGN §3.9): the preamble, the single
// capped parse, the responder and the dependency seam (Env) shared by the services and the
// composition. An EndpointFunc only ever receives a Request built by the preamble, so bypassing
// tenant resolution, the body cap, CSRF, rate limiting, authentication or the sensitive gate does
// not compile.
package httpx

import (
	"errors"

	"github.com/JLugagne/egauth/store/limiter"
)

// Body caps applied by the preamble before the single parse.
const (
	FormBodyCap     int64 = 4 << 10
	WebAuthnBodyCap int64 = 64 << 10
)

// ErrInvalidMeta is returned by Preamble.Wrap for metadata that the preamble cannot enforce.
var ErrInvalidMeta = errors.New("httpx: invalid endpoint metadata")

// Meta is the gate metadata of one auth endpoint. It is computed from the path by internal/routes
// (routes.MetaFor), never written by a service.
type Meta struct {
	Authenticated     bool
	Mutation          bool
	Sensitive         bool
	AcceptsMustChange bool
	IdentifierKeyed   bool
	SetsCookies       bool
	// EndsSession marks an endpoint that only revokes credentials (/logout, /logout-everywhere)
	// and never issues one. Login CSRF cannot apply there, so a cookieless request carrying an
	// Authorization Bearer credential selects Bearer transport without X-Egauth-Transport.
	EndsSession bool
	BodyCap     int64
	// ClientLimit is the limiter class charged per client key; zero charges nothing.
	ClientLimit limiter.Class
	// IdentifierLimit is the limiter class charged per normalised identifier when the request
	// carries one; it is set exactly when IdentifierKeyed.
	IdentifierLimit limiter.Class
	// SessionLimit is the limiter class charged per resumed session lineage, after authentication.
	// It budgets authenticated actions that verify no guessable secret, so clients sharing an
	// address (NAT, IPv6 /64) cannot drain them through the per-client budget (C-71).
	SessionLimit limiter.Class
	// RecipientField names the request field that carries a caller-chosen recipient (a phone number
	// or an e-mail address the endpoint sends a code or a link to). It is set exactly when
	// RecipientLimit is.
	RecipientField string
	// RecipientLimit is the limiter class charged per normalised recipient, after authentication and
	// the sensitive gate. It bounds what one account can send to one recipient however many client
	// addresses it uses (F-HGR-001), and an unauthenticated caller cannot drain it.
	RecipientLimit limiter.Class
}

// Validate reports metadata the preamble cannot enforce: a body cap outside (0, WebAuthnBodyCap],
// a sensitive endpoint that is not authenticated, a session-ending endpoint that is not a mutation
// or is sensitive or identifier-keyed, an identifier key without its limiter class (or
// the reverse), a session limit on an unauthenticated endpoint, a recipient limit without its
// field (or the reverse) or on an unauthenticated endpoint, or an undeclared limiter class.
func (m Meta) Validate() error {
	var errs []error
	if m.BodyCap <= 0 || m.BodyCap > WebAuthnBodyCap {
		errs = append(errs, errors.New("body cap out of range"))
	}
	if m.Sensitive && !m.Authenticated {
		errs = append(errs, errors.New("sensitive endpoint must be authenticated"))
	}
	if m.EndsSession && (!m.Mutation || m.Sensitive || m.IdentifierKeyed) {
		errs = append(errs, errors.New("session-ending endpoint must be a plain mutation"))
	}
	if m.IdentifierKeyed != (m.IdentifierLimit != 0) {
		errs = append(errs, errors.New("identifier key and identifier limit disagree"))
	}
	if m.IdentifierLimit != 0 && (!m.IdentifierLimit.Valid() || !m.IdentifierLimit.PerTenant()) {
		errs = append(errs, errors.New("identifier limit is not a per-tenant class"))
	}
	if m.ClientLimit != 0 && (!m.ClientLimit.Valid() || m.ClientLimit.PerTenant()) {
		errs = append(errs, errors.New("client limit is not a client class"))
	}
	if m.SessionLimit != 0 && (!m.SessionLimit.Valid() || m.SessionLimit.PerTenant() || !m.Authenticated) {
		errs = append(errs, errors.New("session limit needs an authenticated endpoint and a client class"))
	}
	if (m.RecipientField != "") != (m.RecipientLimit != 0) {
		errs = append(errs, errors.New("recipient field and recipient limit disagree"))
	}
	if m.RecipientLimit != 0 && (!m.RecipientLimit.Valid() || !m.RecipientLimit.PerTenant() || !m.Authenticated || !isField(m.RecipientField)) {
		errs = append(errs, errors.New("recipient limit needs an authenticated endpoint, a per-tenant class and a known field"))
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(ErrInvalidMeta, errors.Join(errs...))
}
