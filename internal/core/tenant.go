// Package core owns the sealed authentication vocabulary: the session attributes, the pre-session
// Pending, verified factors, account state, MFA decisions and every transition between them, plus
// the binary codec v1 that persists them opaquely. Fields are unexported, so a value can only be
// produced by the transitions below; which packages may call each transition is enforced by the
// G6 ownership guard.
package core

import (
	"errors"

	"github.com/google/uuid"
)

const maxTenantLen = 128

// TenantID identifies a tenant. It is opaque so that a slug, a user id or any other string cannot
// be used as a tenant without an explicit ParseTenantID. The zero TenantID is the single tenant.
type TenantID struct {
	id string
}

// ParseTenantID validates s as a tenant identifier: 1 to 128 bytes of ASCII letters, digits, '.',
// '_' or '-'. It returns ErrInvalidTenant otherwise; the empty string is refused, the single
// tenant is the zero TenantID.
func ParseTenantID(s string) (TenantID, error) {
	if s == "" || len(s) > maxTenantLen {
		return TenantID{}, ErrInvalidTenant
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
		if !ok {
			return TenantID{}, errors.Join(ErrInvalidTenant, errors.New("invalid character"))
		}
	}
	return TenantID{id: s}, nil
}

// String returns the identifier given to ParseTenantID, or "" for the single tenant.
func (t TenantID) String() string {
	return t.id
}

// IsZero reports whether t is the single tenant.
func (t TenantID) IsZero() bool {
	return t.id == ""
}

// Subject is a user within a tenant. A Subject with a nil User is invalid everywhere.
type Subject struct {
	Tenant TenantID
	User   uuid.UUID
}

// IsZero reports whether s has no user.
func (s Subject) IsZero() bool {
	return s.User == uuid.Nil
}
