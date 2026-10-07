// Package store holds the contracts every egauth store embeds: lifecycle, tenant erasure, expiry
// reaping, durability and the replication cursor.
package store

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/principal"
)

var (
	// ErrNotFound reports that the addressed record does not exist, has expired or was consumed.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict reports a lost compare-and-swap or a uniqueness violation; the caller may re-read.
	ErrConflict = errors.New("store: conflict")
	// ErrCapacity reports that a bounded resource is full and nothing could be evicted.
	ErrCapacity = errors.New("store: capacity exceeded")
)

// Durability tells whether a store keeps its data across process restarts and shares it between
// instances.
type Durability uint8

const (
	// Ephemeral data lives in one process and is lost on restart.
	Ephemeral Durability = iota + 1
	// Shared data survives restarts and is visible to every instance.
	Shared
)

// Valid reports whether d is one of the declared values; the zero Durability is invalid.
func (d Durability) Valid() bool {
	switch d {
	case Ephemeral, Shared:
		return true
	}
	return false
}

// String returns the lowercase name of d, or "invalid".
func (d Durability) String() string {
	switch d {
	case Ephemeral:
		return "ephemeral"
	case Shared:
		return "shared"
	}
	return "invalid"
}

// Base is embedded in every store.
type Base interface {
	// Ping checks connectivity and, for persistent stores, that the schema is at the expected version.
	Ping(ctx context.Context) error
	// EraseTenant removes every record of the tenant and leaves a tombstone where the store keeps one.
	EraseTenant(ctx context.Context, t principal.TenantID) error
	// Durability reports whether the store survives restarts and is shared between instances.
	Durability() Durability
}

// Reaper is embedded by every store whose records carry an expiry.
type Reaper interface {
	// ReapExpired deletes expired records of all tenants and returns how many were removed.
	ReapExpired(ctx context.Context) (int64, error)
}

// Cursor is an opaque, store-issued, monotonic position in a change feed. It is never derived from
// the application clock; the zero Cursor means "from the beginning".
type Cursor struct {
	pos uint64
}

// RestoreCursor rebuilds a cursor from a position the store itself issued (a bigserial value or an
// in-memory counter), never from a clock reading (C-18). It is a `*.Restore*` G6 row: only store
// implementations may call it.
func RestoreCursor(pos uint64) Cursor { return Cursor{pos: pos} }

// Position returns the value given to RestoreCursor, for store implementations.
func (c Cursor) Position() uint64 { return c.pos }

// IsZero reports whether c is the start of the feed.
func (c Cursor) IsZero() bool { return c.pos == 0 }

// After reports whether c is strictly later than o.
func (c Cursor) After(o Cursor) bool { return c.pos > o.pos }
