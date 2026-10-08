// Package identity holds the contract of the account store: users, password credentials,
// federated links, the per-subject security epoch and the lifecycle outbox. Accounts change only
// through intent mutations applied by Apply, which bumps the epoch and queues the outbox in the
// same transaction; there is no generic update.
package identity

import (
	"context"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

// Retention is how long ReapExpired keeps done outbox rows and epoch-log rows; revocation caches
// poll far more often, and a new replica looks epochs up instead of replaying the log.
const Retention = 7 * 24 * time.Hour

// Store persists accounts. Every method is scoped to a tenant, through a TenantID or a Subject.
// Lookups of a missing account return store.ErrNotFound. ReapExpired deletes done outbox rows and
// epoch-log rows older than Retention; it never deletes an account.
type Store interface {
	store.Base
	store.Reaper
	// Apply validates m (Validate), applies it and, in the same transaction, applies EffectsOf(m):
	// bumps security_epoch, appends an epoch-log row and writes OutboxFor(m, ...). On any error
	// nothing is written. It returns ErrInvalidMutation, store.ErrNotFound for an unknown subject,
	// ErrTombstoned for a deleted one, ErrIdentifierTaken for an email, phone or federated identity
	// owned by another live account, and store.ErrConflict for MarkEmailVerified on an email already
	// verified, so a replayed or racing verification never wipes a verified account's credentials.
	Apply(ctx context.Context, m Mutation) (Applied, error)
	// GetUser returns the account of s, tombstoned or not.
	GetUser(ctx context.Context, s principal.Subject) (User, error)
	// FindUser returns the live account of tenant t whose email or phone equals id. It returns
	// ErrInvalidIdentifier for a recovery email, which is not unique.
	FindUser(ctx context.Context, t principal.TenantID, id Identifier) (User, error)
	// GetPassword returns the password credential of s, store.ErrNotFound when it has none.
	GetPassword(ctx context.Context, s principal.Subject) (PasswordCredential, error)
	// RecordPasswordFailure atomically charges one failed password attempt to s under p, using the
	// store's clock: failures older than p.Window decay first, and reaching p.Threshold locks the
	// credential for p.Window.
	RecordPasswordFailure(ctx context.Context, s principal.Subject, p LockoutPolicy) (Lockout, error)
	// ResetPasswordFailures clears the lockout of s after a successful login.
	ResetPasswordFailures(ctx context.Context, s principal.Subject) error
	// FindFederated returns the link of the provider account k to a live account.
	FindFederated(ctx context.Context, k FederatedKey) (FederatedLink, error)
	// ListFederated returns every link of s.
	ListFederated(ctx context.Context, s principal.Subject) ([]FederatedLink, error)
	// CurrentEpoch returns the security epoch of s, tombstoned or not.
	CurrentEpoch(ctx context.Context, s principal.Subject) (uint64, error)
	// EpochsChangedSince returns the epoch changes appended strictly after c, oldest first, and the
	// cursor to resume from. Positions are store-issued: a change stamped with an earlier timestamp
	// is still returned after c (C-18).
	EpochsChangedSince(ctx context.Context, c store.Cursor) ([]EpochChange, store.Cursor, error)
	// PendingOutbox returns at most limit rows that are not done and are due by the store's clock,
	// oldest first, across tenants.
	PendingOutbox(ctx context.Context, limit int) ([]OutboxItem, error)
	// AckOutbox marks row id done. It is idempotent.
	AckOutbox(ctx context.Context, id int64) error
	// FailOutbox counts a failed attempt on row id and defers it to next.
	FailOutbox(ctx context.Context, id int64, next time.Time) error
	// EraseUser hard-deletes the tombstoned account s with its credential and links. It returns
	// ErrNotTombstoned unless Tombstone was applied, and store.ErrConflict while an outbox row of s
	// for another Component is not done.
	EraseUser(ctx context.Context, s principal.Subject) error
}
