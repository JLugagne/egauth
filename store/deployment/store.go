// Package deployment holds the persistence contract of deployment-wide sealed values and instance
// liveness.
package deployment

import (
	"context"
	"time"

	"github.com/JLugagne/egauth/store"
	"github.com/google/uuid"
)

// LivenessWindow is how long, in store time, an instance counts as live after its last heartbeat.
// It is a library constant shared by every implementation. Callers heartbeat at least every
// LivenessWindow / 3, and ReapExpired removes instances unseen for longer than LivenessWindow.
const LivenessWindow = 90 * time.Second

// Instance is one running process that heartbeats into the store.
type Instance struct {
	ID         uuid.UUID
	StartedAt  time.Time
	LastSeenAt time.Time
}

// Replacement is the compare-and-swap of a sealed value.
type Replacement struct {
	Old []byte
	New []byte
}

// Store keeps sealed deployment values (such as the KEK canary) and counts live instances. Stores
// persist opaque bytes and never see a KEK.
type Store interface {
	store.Base
	store.Reaper

	// GetSealed returns the value under key, or store.ErrNotFound.
	GetSealed(ctx context.Context, key string) ([]byte, error)
	// PutSealedIfAbsent stores sealed unless key exists, and reports whether it stored.
	PutSealedIfAbsent(ctx context.Context, key string, sealed []byte) (bool, error)
	// ReplaceSealed swaps r.Old for r.New only while the stored value equals r.Old, and reports
	// whether it did. It returns store.ErrNotFound when key is absent.
	ReplaceSealed(ctx context.Context, key string, r Replacement) (bool, error)
	// Heartbeat records the instance as seen now, by store time, and returns every instance seen
	// within LivenessWindow, the caller included.
	Heartbeat(ctx context.Context, instance uuid.UUID) ([]Instance, error)
}
