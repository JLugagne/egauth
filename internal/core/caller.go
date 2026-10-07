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
)

// Caller is the sealed identity of whoever invokes a facade method. It cannot be assembled outside
// core, so a System caller can only come from the composition object. The zero Caller has kind 0
// and must be refused.
type Caller struct {
	kind    CallerKind
	tenant  TenantID
	session SessionAttrs
	subject Subject
	apiKey  uuid.UUID
	reason  string
}

// SessionCaller returns the caller of an interactive session. It returns ErrInvalidArgument for
// zero attributes.
func SessionCaller(a SessionAttrs) (Caller, error) {
	if a.version == 0 {
		return Caller{}, ErrInvalidArgument
	}
	return Caller{kind: CallerSession, tenant: a.subject.Tenant, session: a.clone(), subject: a.subject}, nil
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

// APIKey returns the API key id, and false unless the caller is an API key.
func (c Caller) APIKey() (uuid.UUID, bool) { return c.apiKey, c.kind == CallerAPIKey }

// Reason returns the audited reason of a System caller, or "".
func (c Caller) Reason() string { return c.reason }
