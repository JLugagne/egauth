package keys

import (
	"errors"
	"time"
)

var (
	// ErrInvalidExpiry reports a zero Expiry or a negative duration (X-16).
	ErrInvalidExpiry = errors.New("keys: invalid expiry")
	// ErrUnboundedOverlap reports a NeverExpire rotation overlap: a retired key must stop verifying
	// at a fixed time (X-16).
	ErrUnboundedOverlap = errors.New("keys: rotation overlap must be bounded")
)

type expiryKind uint8

const (
	expiryAfter expiryKind = iota + 1
	expiryNever
	expiryDefault
)

// Expiry is a key or overlap lifetime. The zero Expiry is invalid, so an omitted field can never
// silently mean "forever" or "now".
type Expiry struct {
	kind expiryKind
	d    time.Duration
}

// ExpireAfter returns an Expiry of d. It returns ErrInvalidExpiry when d is negative.
func ExpireAfter(d time.Duration) (Expiry, error) {
	if d < 0 {
		return Expiry{}, ErrInvalidExpiry
	}
	return Expiry{kind: expiryAfter, d: d}, nil
}

// NeverExpire returns an Expiry that has no end.
func NeverExpire() Expiry { return Expiry{kind: expiryNever} }

// DefaultExpiry returns an Expiry that resolves to the library default of the field it fills.
func DefaultExpiry() Expiry { return Expiry{kind: expiryDefault} }

// Valid reports whether e was built by one of the constructors.
func (e Expiry) Valid() bool {
	switch e.kind {
	case expiryAfter:
		return e.d >= 0
	case expiryNever, expiryDefault:
		return true
	}
	return false
}

// IsNever reports whether e has no end.
func (e Expiry) IsNever() bool { return e.kind == expiryNever }

// At resolves e against now. A default Expiry resolves to fallback, which must not be negative;
// NeverExpire resolves to the zero time. It returns ErrInvalidExpiry for an invalid Expiry.
func (e Expiry) At(now time.Time, fallback time.Duration) (time.Time, error) {
	switch e.kind {
	case expiryAfter:
		if e.d < 0 {
			return time.Time{}, ErrInvalidExpiry
		}
		return now.Add(e.d), nil
	case expiryNever:
		return time.Time{}, nil
	case expiryDefault:
		if fallback < 0 {
			return time.Time{}, ErrInvalidExpiry
		}
		return now.Add(fallback), nil
	}
	return time.Time{}, ErrInvalidExpiry
}

// OverlapUntil resolves e as a rotation overlap starting at retiredAt, into Rotation.OverlapUntil. A
// default Expiry resolves to fallback, which must be positive. It returns ErrUnboundedOverlap for
// NeverExpire and ErrInvalidExpiry for an invalid Expiry or fallback.
func (e Expiry) OverlapUntil(retiredAt time.Time, fallback time.Duration) (time.Time, error) {
	if e.kind == expiryNever {
		return time.Time{}, ErrUnboundedOverlap
	}
	if e.kind == expiryDefault && fallback <= 0 {
		return time.Time{}, ErrInvalidExpiry
	}
	return e.At(retiredAt, fallback)
}
