package revoke

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/keys"
)

// KeySource is the part of keys.Store the keyset cache follows.
type KeySource interface {
	ChangesSince(ctx context.Context, c store.Cursor) ([]keys.Change, store.Cursor, error)
}

// Keys caches one keyset V per tenant, following ChangesSince. The feed names tenants, not key
// ids, so an entry is a tenant's whole keyset and a key id absent from a fresh entry is unknown
// without a store read. internal/keys owns the only instance and supplies the load function that
// opens the keyset. It is safe for concurrent use.
type Keys[V any] struct {
	*follower[principal.TenantID, V]
}

// NewKeys returns a stopped keyset cache over src whose misses call load. load must report
// store.ErrNotFound only for an answer that may be repeated, never to mean "empty"; any other error
// becomes ErrUnavailable. It returns ErrInvalidConfig for a nil src or load, or a negative
// capacity.
func NewKeys[V any](src KeySource, load func(ctx context.Context, t principal.TenantID) (V, error), cfg Config) (*Keys[V], error) {
	if src == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("revoke: nil key source"))
	}
	feed := func(ctx context.Context, c store.Cursor) ([]principal.TenantID, store.Cursor, error) {
		changes, next, err := src.ChangesSince(ctx, c)
		if err != nil {
			return nil, c, err
		}
		out := make([]principal.TenantID, len(changes))
		for i, ch := range changes {
			out[i] = ch.Tenant
		}
		return out, next, nil
	}
	scope := func(t principal.TenantID) audit.Scope { return audit.Scope{TenantID: t.String()} }
	f, err := newFollower("keys", cfg, feed, load, scope)
	if err != nil {
		return nil, err
	}
	return &Keys[V]{follower: f}, nil
}

// Get returns the keyset of t. It returns ErrUnavailable joined with the cause when load fails
// with anything but store.ErrNotFound.
func (k *Keys[V]) Get(ctx context.Context, t principal.TenantID) (V, error) {
	return k.get(ctx, t)
}

// Forget drops the cached keyset of t and voids every lookup in flight, so a write made by this
// instance is visible to its next Get without waiting for the poll.
func (k *Keys[V]) Forget(t principal.TenantID) {
	k.forget(t)
}
