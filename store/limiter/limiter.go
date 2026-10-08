// Package limiter holds the rate-limiter contract. Budgets are library constants of each Class; no
// call site passes them.
package limiter

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
)

const maxValueLen = 256

// Class names a budgeted action. Its value is part of the persisted key, so it is never renumbered.
// The zero Class is invalid.
type Class uint8

const (
	// LoginIdentifier budgets password attempts per normalised identifier.
	LoginIdentifier Class = 1
	// LoginClient budgets password attempts per client address.
	LoginClient Class = 2
	// CodeRequestIdentifier budgets emailed or texted code requests per normalised identifier.
	CodeRequestIdentifier Class = 3
	// CodeRequestClient budgets code requests per client address.
	CodeRequestClient Class = 4
	// RegisterClient budgets registrations per client address.
	RegisterClient Class = 5
	// SelfTest is used only by the startup probe of New.
	SelfTest Class = 6
	classEnd Class = 7
)

// Budget is a token bucket: Burst tokens, one more every Refill.
type Budget struct {
	Burst  int
	Refill time.Duration
}

// PerInstance returns the share of b one of n live instances enforces when each keeps its own
// buckets: Burst divided by n, never below one, and Refill multiplied by n, so n instances together
// never exceed b. An n below 2 returns b unchanged.
func (b Budget) PerInstance(n int) Budget {
	if n < 2 {
		return b
	}
	return Budget{Burst: max(b.Burst/n, 1), Refill: b.Refill * time.Duration(n)}
}

// Valid reports whether c is a declared class.
func (c Class) Valid() bool { return c >= LoginIdentifier && c < classEnd }

// String returns the lowercase name of c, or "invalid".
func (c Class) String() string {
	switch c {
	case LoginIdentifier:
		return "login_identifier"
	case LoginClient:
		return "login_client"
	case CodeRequestIdentifier:
		return "code_request_identifier"
	case CodeRequestClient:
		return "code_request_client"
	case RegisterClient:
		return "register_client"
	case SelfTest:
		return "selftest"
	}
	return "invalid"
}

// Budget returns the library budget of c; the zero Budget for an invalid class, which allows
// nothing.
func (c Class) Budget() Budget {
	switch c {
	case LoginIdentifier:
		return Budget{Burst: 10, Refill: 6 * time.Minute}
	case LoginClient:
		return Budget{Burst: 30, Refill: 2 * time.Minute}
	case CodeRequestIdentifier:
		return Budget{Burst: 5, Refill: 12 * time.Minute}
	case CodeRequestClient:
		return Budget{Burst: 20, Refill: 3 * time.Minute}
	case RegisterClient:
		return Budget{Burst: 10, Refill: 6 * time.Minute}
	case SelfTest:
		return Budget{Burst: 3, Refill: time.Hour}
	}
	return Budget{}
}

// PerTenant reports whether c budgets a per-tenant value (a normalised identifier), so that attempts
// in one tenant never drain the bucket of the same identifier in another. Client-address classes
// are deployment-wide.
func (c Class) PerTenant() bool {
	return c == LoginIdentifier || c == CodeRequestIdentifier
}

// Key addresses one bucket. Value is the normalised identifier or the client key, never a subject.
// Tenant is part of the bucket for a PerTenant class and must be the zero TenantID otherwise.
type Key struct {
	Class  Class
	Tenant principal.TenantID
	Value  string
}

// Valid reports whether the class is declared, the tenant is set only for a PerTenant class, and
// the value is non-empty and at most 256 bytes.
func (k Key) Valid() bool {
	if !k.Class.Valid() || k.Value == "" || len(k.Value) > maxValueLen {
		return false
	}
	return k.Class.PerTenant() || k.Tenant == principal.TenantID{}
}

// TenantPrefix returns the prefix shared by the StorageKey of every key of class c and tenant t, and
// by no other key, so EraseTenant can delete them without reading Value.
func TenantPrefix(c Class, t principal.TenantID) []byte {
	id := t.String()
	return append([]byte{byte(c), byte(len(id))}, id...)
}

// StorageKey is the only form of k a Limiter may persist or index: TenantPrefix followed by the
// SHA-256 of Value, so a normalised identifier (often an email) is never stored in clear. It is at
// most 162 bytes, and two distinct valid keys never share one.
func (k Key) StorageKey() []byte {
	sum := sha256.Sum256([]byte(k.Value))
	return append(TenantPrefix(k.Class, k.Tenant), sum[:]...)
}

// Decision is the outcome of one Allow call.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
}

// Limiter charges one token from the bucket of a key.
//
// Allow returns an error for an invalid Key and never allows on a store error: callers fail
// closed. Implementations are safe for concurrent use. Buckets are addressed by Key.StorageKey
// only; Value is never persisted, logged or indexed.
//
// A bucket that has refilled to Burst is equivalent to an absent one. ReapExpired deletes those
// buckets, so storage stays bounded by the keys charged within one full refill, however many random
// values an attacker sprays. EraseTenant deletes at once every bucket whose StorageKey starts with
// the TenantPrefix of a PerTenant class and the tenant, instead of leaving them to ReapExpired.
//
// A Shared Limiter enforces Class.Budget. New refuses an Ephemeral Limiter beside Shared stores
// unless it implements InstanceScaler.
type Limiter interface {
	store.Base
	store.Reaper

	// Allow consumes one token and reports whether the action may proceed; RetryAfter is set when it
	// may not.
	Allow(ctx context.Context, key Key) (Decision, error)
}

// InstanceScaler is the channel through which New hands an Ephemeral Limiter the live instance
// count from deployment.Store heartbeats. From then on the limiter enforces
// Class.Budget().PerInstance(n), so per-process buckets never add up to more than the library
// budget (DESIGN section 3.3 step 4). SetInstances is safe for concurrent use with Allow; an n below
// 1 counts as 1.
type InstanceScaler interface {
	SetInstances(n int)
}
