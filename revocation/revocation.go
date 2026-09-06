// Package revocation provides a unified, cross-module revocation bus (issue #72). It decouples
// the events that should invalidate live credentials — a password change, an account being
// disabled or deleted, a refresh-token reuse detection, a tenant being torn down, an explicit
// "log out everywhere" — from the modules that actually hold revocable state (sessions, refresh
// token families, in-flight auth flows).
//
// A producer (identity service, tokens service, an admin action) publishes a Revocation
// describing WHAT should be revoked and WHY. Subscribers registered for the relevant TargetType
// (plus any wildcard TargetAll subscribers) each react — revoking sessions, burning token
// families, and so on. The bus itself is intentionally policy-free and store-agnostic: it only
// fans a revocation out to whoever has opted in to hear about it.
//
// NewMemBus returns the zero-dependency in-process implementation, suitable for single-process
// deployments and tests. A distributed Bus (e.g. backed by a queue or Postgres LISTEN/NOTIFY)
// can be substituted without changing producers or subscribers, since both depend only on the
// Bus and Handler interfaces.
//
// The hook constructors (NewAccountRevocationHook, NewTenantRevocationHook) adapt the bus to the
// narrow function signatures the producing modules already use for their post-mutation callbacks,
// so wiring revocation into an existing service is a one-liner rather than a re-architecture.
package revocation

import (
	"context"
	"time"
)

// TargetType classifies what a Revocation points at, so subscribers can opt in to exactly the
// granularity they act on. TargetAll is the wildcard: a subscriber registered for it receives
// every published revocation regardless of its concrete TargetType.
type TargetType string

const (
	TargetUser        TargetType = "user"         // everything tied to one user across a tenant
	TargetTenant      TargetType = "tenant"       // everything tied to one tenant
	TargetSession     TargetType = "session"      // a single server-side session
	TargetTokenFamily TargetType = "token_family" // a single refresh-token family
	TargetAll         TargetType = "*"            // wildcard subscription: receive every revocation
)

// Scope narrows WHAT KIND of credential a revocation should tear down. A producer that only
// needs to evict interactive sessions (e.g. a password change that should not kill a long-lived
// API token family) uses ScopeInteractive; a full account/tenant teardown uses ScopeAll.
type Scope string

const (
	ScopeAll          Scope = "all"         // every credential kind: sessions, tokens, flows
	ScopeInteractive  Scope = "interactive" // interactive sessions only (browser/app logins)
	ScopeSessionsOnly Scope = "sessions"    // server-side sessions only
	ScopeTokensOnly   Scope = "tokens"      // stateless/refresh token families only
)

// Reason records WHY a revocation was issued. It is carried on the Revocation for audit and for
// subscribers that need to differentiate (e.g. token_reuse_detected may force a stricter teardown
// than logout_everywhere). Values are stable strings — downstream code may serialize them.
type Reason string

const (
	ReasonPasswordChanged    Reason = "password_changed"
	ReasonPasswordReset      Reason = "password_reset"
	ReasonAccountDisabled    Reason = "account_disabled"
	ReasonAccountDeleted     Reason = "account_deleted"
	ReasonTokenReuseDetected Reason = "token_reuse_detected"
	ReasonLogoutEverywhere   Reason = "logout_everywhere"
	ReasonTenantDeactivated  Reason = "tenant_deactivated"
	ReasonTenantDeleted      Reason = "tenant_deleted"
)

// Revocation is the message published on the Bus. TargetID is the string form of the target's
// identifier (a user UUID, a tenant ID, a session ID, or a token-family ID) so the struct stays
// free of any single module's ID type. CutoffTime, when set, lets a subscriber revoke only
// credentials issued before it (e.g. sessions older than the password change), leaving newer
// ones — such as the very session that performed the change — alive.
type Revocation struct {
	TenantID   string
	TargetType TargetType
	TargetID   string
	Scope      Scope
	Reason     Reason
	CutoffTime time.Time
	Metadata   map[string]any
}

// Handler reacts to a Revocation a subscriber cares about. A Handler that returns an error does
// not stop the fan-out: the Bus collects every handler's error and reports them joined, so one
// failing subscriber cannot silently prevent the others from revoking.
type Handler interface {
	HandleRevocation(ctx context.Context, rev Revocation) error
}

// HandlerFunc adapts a plain function to the Handler interface.
type HandlerFunc func(ctx context.Context, rev Revocation) error

// HandleRevocation implements Handler.
func (f HandlerFunc) HandleRevocation(ctx context.Context, rev Revocation) error {
	return f(ctx, rev)
}

// Bus fans a published Revocation out to the Handlers subscribed to its TargetType (and to any
// wildcard TargetAll subscribers). Subscribe registers a handler; Publish dispatches. Publish
// aggregates handler errors and honors context cancellation.
type Bus interface {
	Subscribe(target TargetType, h Handler)
	Publish(ctx context.Context, rev Revocation) error
}
