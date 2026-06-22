package egauth

import "github.com/google/uuid"

// PrincipalKind classifies the authenticated entity making a request. It lets egauth tell the
// application whether a request is a user action or a machine action without requiring the
// application to inspect token internals.
//
// The zero value is the empty string, which [Actor.IsHuman] treats as [User] so that a
// zero-value Actor (e.g. in tests that do not set Kind) is always safe and human.
type PrincipalKind string

const (
	// User indicates an interactively authenticated human (session or short-lived JWT).
	// IsHuman returns true; IsMachine returns false.
	User PrincipalKind = "user"

	// PAT indicates a Personal Access Token that acts on behalf of a human.
	// The token carries explicit Scopes; the underlying subject is still the owning user.
	// IsHuman returns true; IsMachine returns false.
	PAT PrincipalKind = "pat"

	// Service indicates a machine/service identity decoupled from any human.
	// The token's subject is the key's own ID (not a user). IsMachine returns true.
	Service PrincipalKind = "service"
)

// Actor represents the authenticated entity making a request.
// It is explicitly passed as an argument to handlers, never transported via context.Context.
//
// Kind classifies the principal as a human (User or PAT) or a machine (Service). A zero-value
// Actor has Kind == "" which is treated as User by IsHuman/IsMachine, making it safe for tests
// that do not need principal classification.
type Actor struct {
	// UserID is the user's UUID. Set for User and PAT actors; for Service actors the subject
	// is the key's own ID, which is stored in KeyID rather than here.
	UserID uuid.UUID
	// TenantID is the tenant scope in which this actor operates.
	TenantID string
	// Kind classifies the actor as User, PAT, or Service. The zero value behaves as User.
	Kind PrincipalKind
	// KeyID is the API key UUID. Non-zero for PAT and Service actors; empty for User actors.
	KeyID uuid.UUID
	// Scopes holds the set of permission scopes carried by this actor's token. egauth does not
	// interpret or enforce scopes — they are provided verbatim for the application's middleware
	// to act on (e.g. via WithRequiredScopes).
	Scopes []string
}

// IsHuman reports whether the actor represents a human-initiated request. It returns true for
// User (interactive login) and PAT (personal access token acting on behalf of a user), and for
// the zero value of Kind.
func (a Actor) IsHuman() bool {
	return a.Kind == User || a.Kind == PAT || a.Kind == ""
}

// IsMachine reports whether the actor represents a machine/service identity. It returns true
// only when Kind is Service.
func (a Actor) IsMachine() bool {
	return a.Kind == Service
}

// HasScope reports whether scope s is present in the actor's Scopes list.
// It returns false for a nil or empty Scopes slice.
func (a Actor) HasScope(s string) bool {
	for _, sc := range a.Scopes {
		if sc == s {
			return true
		}
	}
	return false
}

// HasAllScopes reports whether every requested scope is present in the actor's Scopes list.
// Vacuous truth: calling with no arguments always returns true.
// It returns false for a nil or empty Scopes slice when at least one scope is requested.
func (a Actor) HasAllScopes(scopes ...string) bool {
	for _, s := range scopes {
		if !a.HasScope(s) {
			return false
		}
	}
	return true
}

// HasAnyScope reports whether at least one of the requested scopes is present in the actor's
// Scopes list. Calling with no arguments always returns false (no scope can satisfy an empty
// requirement set). It returns false for a nil or empty Scopes slice.
func (a Actor) HasAnyScope(scopes ...string) bool {
	for _, s := range scopes {
		if a.HasScope(s) {
			return true
		}
	}
	return false
}
