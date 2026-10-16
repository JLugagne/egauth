// Package session defines the session Backend that the JWT and stateful implementations satisfy,
// and owns renewal (core.Renew) and unsealing on the session path.
package session

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/store"
)

// Backend issues, resumes, reissues and ends sessions. Credentials travel only through
// internal/cookie or the Authorization header, on the transport sealed in the attributes. Start is
// called only by internal/issuance and internal/flow, Reissue only by internal/issuance (G6). As a
// lifecycle.Subscriber it revokes sessions on every account event (DESIGN §7.2).
type Backend interface {
	// Start persists a new session for a and its claims c and writes its credentials to w.
	Start(ctx context.Context, w http.ResponseWriter, a core.SessionAttrs, c core.SealedClaims) error
	// Resume authenticates r for tenant, the tenant the request resolved to: it checks the
	// credential, its sealed tenant, the live family or row, the subject's current epoch and the
	// absolute lifetime, renews when due, and rewrites credentials on w when they changed. A
	// credential sealed for another tenant returns ErrTenantMismatch before anything is renewed,
	// consumed or written (DESIGN §6.10). Any failure returns an error and no session.
	Resume(ctx context.Context, w http.ResponseWriter, r *http.Request, tenant core.TenantID) (Resumed, error)
	// Reissue atomically replaces the session cur with one for a, which must keep cur's subject and
	// lineage; it returns store.ErrConflict, and issues nothing, once cur is no longer live (C-33).
	// cur.ID() is all the store needs: tokens.ReissueRequest.Family or sessions.ReplaceRequest.Previous.
	Reissue(ctx context.Context, w http.ResponseWriter, cur Handle, a core.SessionAttrs) error
	// End revokes the session presented by r and clears its credentials on w. It is idempotent.
	End(ctx context.Context, w http.ResponseWriter, r *http.Request) error
	// Live returns nil while the stored session h names is live by the rules of Resume: not ended,
	// revoked, replaced by Reissue nor past its absolute lifetime. It returns ErrEnded otherwise, and
	// an error joined with httpx.ErrUnavailable when the store cannot answer. Facades call it for
	// every session Caller.
	Live(ctx context.Context, h Handle) error
	// Durability reports whether sessions survive restarts and are shared between instances.
	Durability() store.Durability
	lifecycle.Subscriber
}

// ErrTenantMismatch reports a credential sealed for another tenant than the resolved one. Nothing
// was consumed, so the caller refuses the request without clearing the credential.
var ErrTenantMismatch = errors.New("session: credential sealed for another tenant")

// ErrEnded reports a stored session that is no longer live.
var ErrEnded = errors.New("session: the session is no longer live")

// ErrHandleMismatch reports a Handle or Resumed whose parts do not describe the same session.
var ErrHandleMismatch = errors.New("session: handle does not match the session attributes")

// Handle identifies the stored session (refresh family or session row) behind a resumed request,
// for Reissue and End. It is bound to the subject and lineage of the attributes it was made from.
// Its ID is the key of every by-session store call (tokens.Store.Reissue and RevokeFamily,
// sessions.Store.Replace and RevokeSession) and the Family of lifecycle.SessionEnded.
type Handle struct {
	subject core.Subject
	lineage uuid.UUID
	id      uuid.UUID
	key     string
}

// NewHandle binds the stored session id to a. It returns ErrHandleMismatch for zero attributes or a
// nil id.
func NewHandle(a core.SessionAttrs, id uuid.UUID) (Handle, error) {
	if a.IsZero() || a.Subject().IsZero() || a.Lineage() == uuid.Nil || id == uuid.Nil {
		return Handle{}, ErrHandleMismatch
	}
	return Handle{subject: a.Subject(), lineage: a.Lineage(), id: id}, nil
}

// NewKeyedHandle is NewHandle for a backend that finds its stored session by a lookup key rather
// than by id (the stateful token digest). It also returns ErrHandleMismatch for an empty key.
func NewKeyedHandle(a core.SessionAttrs, id uuid.UUID, key []byte) (Handle, error) {
	if len(key) == 0 {
		return Handle{}, ErrHandleMismatch
	}
	h, err := NewHandle(a, id)
	if err != nil {
		return Handle{}, err
	}
	h.key = string(key)
	return h, nil
}

// HandleOf returns the handle of the stored session a session Caller was resumed from, for
// Backend.Live. It returns ErrHandleMismatch for any other caller.
func HandleOf(c core.Caller) (Handle, error) {
	a, ok := c.Session()
	id, key, stored := c.Stored()
	if !ok || !stored {
		return Handle{}, ErrHandleMismatch
	}
	if len(key) == 0 {
		return NewHandle(a, id)
	}
	return NewKeyedHandle(a, id, key)
}

// Key returns the lookup key of a keyed handle, nil otherwise.
func (h Handle) Key() []byte { return []byte(h.key) }

// ID returns the refresh family id (JWT) or the session row id (stateful).
func (h Handle) ID() uuid.UUID { return h.id }

func (h Handle) Subject() core.Subject { return h.subject }

// Lineage returns the session id that Reissue must preserve.
func (h Handle) Lineage() uuid.UUID { return h.lineage }

// IsZero reports whether h was not built by NewHandle.
func (h Handle) IsZero() bool { return h.id == uuid.Nil }

// Resumed is an authenticated session: its attributes, its claims and its handle, all describing
// the same subject and lineage.
type Resumed struct {
	attrs  core.SessionAttrs
	claims core.SealedClaims
	handle Handle
}

// NewResumed assembles the result of Resume. It returns ErrHandleMismatch unless h was made from
// a session with the subject and lineage of a.
func NewResumed(a core.SessionAttrs, c core.SealedClaims, h Handle) (Resumed, error) {
	if h.IsZero() || a.IsZero() || h.subject != a.Subject() || h.lineage != a.Lineage() {
		return Resumed{}, ErrHandleMismatch
	}
	return Resumed{attrs: a, claims: c, handle: h}, nil
}

func (r Resumed) Attrs() core.SessionAttrs { return r.attrs }

func (r Resumed) Claims() core.SealedClaims { return r.claims }

func (r Resumed) Handle() Handle { return r.handle }

// Caller returns the session Caller of r, bound to its stored session.
func (r Resumed) Caller() (core.Caller, error) {
	return core.SessionCaller(r.attrs, r.handle.id, []byte(r.handle.key))
}
