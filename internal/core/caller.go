package core

import (
	"errors"

	"github.com/google/uuid"
)

// CallerKind says who acts through a facade.
type CallerKind uint8

const (
	// CallerSession carries the session attributes, read through Caller.Session.
	CallerSession CallerKind = iota + 1
	// CallerAPIKey is always refused by facades; Caller.APIKey returns the key id.
	CallerAPIKey
	// CallerSystem is a background job; only the composition object mints it.
	CallerSystem
	// CallerResourceToken is the holder of an audience-bound resource token on a resource server.
	// It is always refused by facades: the token is a delegated, short-lived credential, not a
	// first-party session (DESIGN §3.7).
	CallerResourceToken
)

// Caller is the sealed identity of whoever invokes a facade method. It cannot be assembled outside
// core, so a System caller can only come from the composition object. The zero Caller has kind 0
// and must be refused.
type Caller struct {
	kind    CallerKind
	tenant  TenantID
	session SessionAttrs
	stored  uuid.UUID
	key     string
	subject Subject
	apiKey  uuid.UUID
	reason  string
}

// SessionCaller returns the caller of an interactive session resumed from the stored session
// stored (refresh family or session row id); key is the stored session's lookup key when its
// backend needs one, nil otherwise. A Caller never outlives its session: facades refuse it once
// the stored session ended (doclint:enforced-by egauth.TestFacadesRefuseASessionCallerOnceItsSessionEnded).
// It returns ErrInvalidArgument for zero attributes or a nil stored id.
func SessionCaller(a SessionAttrs, stored uuid.UUID, key []byte) (Caller, error) {
	if a.version == 0 || stored == uuid.Nil {
		return Caller{}, ErrInvalidArgument
	}
	return Caller{kind: CallerSession, tenant: a.subject.Tenant, session: a.clone(), stored: stored, key: string(key), subject: a.subject}, nil
}

// ResourceTokenCaller returns the caller of a resource token carrying a. It returns
// ErrInvalidArgument for zero attributes.
func ResourceTokenCaller(a SessionAttrs) (Caller, error) {
	if a.version == 0 {
		return Caller{}, ErrInvalidArgument
	}
	return Caller{kind: CallerResourceToken, tenant: a.subject.Tenant, subject: a.subject}, nil
}

// APIKeyCaller returns the caller of an API key owned by s. It returns ErrInvalidArgument for a
// zero subject or key id.
func APIKeyCaller(s Subject, key uuid.UUID) (Caller, error) {
	if s.IsZero() || key == uuid.Nil {
		return Caller{}, ErrInvalidArgument
	}
	return Caller{kind: CallerAPIKey, tenant: s.Tenant, subject: s, apiKey: key}, nil
}

// SystemCaller returns a background caller acting on tenant t for an audited reason. It returns
// ErrInvalidArgument for an empty reason.
func SystemCaller(t TenantID, reason string) (Caller, error) {
	if reason == "" {
		return Caller{}, errors.Join(ErrInvalidArgument, errors.New("reason"))
	}
	return Caller{kind: CallerSystem, tenant: t, reason: reason}, nil
}

// Kind returns the caller kind, or 0 for the zero Caller.
func (c Caller) Kind() CallerKind { return c.kind }

func (c Caller) Tenant() TenantID { return c.tenant }

// Subject returns the acting user, and false for a System caller.
func (c Caller) Subject() (Subject, bool) { return c.subject, !c.subject.IsZero() }

// Session returns the session attributes, and false unless the caller is a session.
func (c Caller) Session() (SessionAttrs, bool) {
	return c.session.clone(), c.kind == CallerSession
}

// Stored returns the stored session id and lookup key of a session caller, and false otherwise.
func (c Caller) Stored() (uuid.UUID, []byte, bool) {
	return c.stored, []byte(c.key), c.kind == CallerSession
}

// APIKey returns the API key id, and false unless the caller is an API key.
func (c Caller) APIKey() (uuid.UUID, bool) { return c.apiKey, c.kind == CallerAPIKey }

// Reason returns the audited reason of a System caller, or "".
func (c Caller) Reason() string { return c.reason }
