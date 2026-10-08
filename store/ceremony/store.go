package ceremony

import (
	"context"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

// Store persists stored ceremonies and the single-use marks of stateless ones. Every method is
// scoped to a tenant and a kind; a record of another tenant or kind is never returned. Lookups of a
// missing or expired record return store.ErrNotFound. There is no lookup by scope: every stored
// record, including an authenticated phone verification scoped to its subject, is found by the
// digest of its random 256-bit handle, and the caller checks Record.ScopedTo against the session.
type Store interface {
	store.Base
	store.Reaper
	// Put inserts r, then evicts the oldest live records of the same tenant, kind and scope beyond
	// Kind.MaxLivePerScope and, when Kind.MaxLivePerTenant is non-zero, the oldest of the same tenant
	// and kind beyond it; it returns how many it evicted and never refuses for capacity. Records of
	// another scope are never evicted. It refuses with the error of r.Validate, so a stateless kind
	// gets ErrStatelessKind and a short handle ErrHandleTooShort, and returns store.ErrConflict for
	// a duplicate handle.
	Put(ctx context.Context, r Record) (evicted int, err error)
	// Peek returns the live record without consuming it.
	Peek(ctx context.Context, t principal.TenantID, k Kind, handleHash []byte) (Record, error)
	// Consume atomically deletes and returns the live record: of concurrent callers exactly one gets
	// it and the others get store.ErrNotFound.
	Consume(ctx context.Context, t principal.TenantID, k Kind, handleHash []byte) (Record, error)
	// RecordFailure charges one failed verification to the live record and returns how many remain;
	// at zero the record is deleted.
	RecordFailure(ctx context.Context, t principal.TenantID, k Kind, handleHash []byte) (remaining int, err error)
	// MarkConsumed marks a stateless handle used until its expiry and reports whether this call was
	// the first; a later call before until returns false. It returns ErrStoredKind unless k is
	// stateless.
	MarkConsumed(ctx context.Context, t principal.TenantID, k Kind, handleHash []byte, until time.Time) (first bool, err error)
	// DeleteForScope deletes the records of tenant t whose scope hash is scopeHash, restricted to
	// kinds when any are given, and returns how many it deleted.
	DeleteForScope(ctx context.Context, t principal.TenantID, scopeHash []byte, kinds ...Kind) (int64, error)
}
