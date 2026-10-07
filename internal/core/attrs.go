package core

import (
	"bytes"
	"slices"
	"time"

	"github.com/google/uuid"
)

const codecVersion uint8 = 1

type credentialUse struct {
	factor Factor
	id     []byte
}

func cloneCreds(c []credentialUse) []credentialUse {
	if len(c) == 0 {
		return nil
	}
	out := make([]credentialUse, len(c))
	for i, u := range c {
		out[i] = credentialUse{factor: u.factor, id: cloneBytes(u.id)}
	}
	return out
}

func credentialClash(existing []credentialUse, f Factor, id []byte) bool {
	var other Factor
	switch f {
	case FactorPasskey:
		other = FactorPasskeyStepUp
	case FactorPasskeyStepUp:
		other = FactorPasskey
	default:
		return false
	}
	return slices.ContainsFunc(existing, func(u credentialUse) bool {
		return u.factor == other && bytes.Equal(u.id, id)
	})
}

// SessionAttrs is established-session state. It is produced only by the core transitions (owned
// by internal/issuance and, for Renew, internal/session), carried verbatim by rotation, persisted
// opaquely as Sealed, and read by applications through accessors. The zero value is invalid.
type SessionAttrs struct {
	version         uint8
	lineage         uuid.UUID
	subject         Subject
	factors         []Factor
	credentialIDs   []credentialUse
	primaryAt       time.Time
	secondAt        time.Time
	epoch           uint64
	mustChange      bool
	remember        bool
	returnTo        string
	transport       Transport
	provider        string
	createdAt       time.Time
	claimsFetchedAt time.Time
}

// IsZero reports whether a was not produced by a transition.
func (a SessionAttrs) IsZero() bool {
	return a.version == 0
}

func (a SessionAttrs) Subject() Subject { return a.subject }

// Lineage returns the session id: stable across rotation, reissue and reauthentication.
func (a SessionAttrs) Lineage() uuid.UUID { return a.lineage }

// Factors returns the verified factors, ordered by code.
func (a SessionAttrs) Factors() []Factor { return slices.Clone(a.factors) }

// HasFactor reports whether f was verified in this session. It is false for the zero Factor.
func (a SessionAttrs) HasFactor(f Factor) bool {
	return f.Valid() && slices.Contains(a.factors, f)
}

// MultiFactor reports whether the session holds a primary and a second factor, or a passkey with
// user verification.
func (a SessionAttrs) MultiFactor() bool { return multiFactor(a.factors) }

// AMR returns RFC 8176 values for interoperability output only, plus "mfa" when MultiFactor.
// Authorization decisions must use HasFactor or MultiFactor, never AMR.
func (a SessionAttrs) AMR() []string { return amrOf(a.factors) }

// PrimaryAt returns when the latest primary factor was verified.
func (a SessionAttrs) PrimaryAt() time.Time { return a.primaryAt }

// SecondAt returns when the latest second factor (or passkey with user verification) was
// verified, or the zero time. Enrolling a factor does not set it (C-45).
func (a SessionAttrs) SecondAt() time.Time { return a.secondAt }

// FreshWithin reports whether the session was authenticated within d of now. The check is
// role-aware (C-44): the primary factor must be within d, and so must SecondAt whenever the
// session holds a second factor or is MultiFactor (a passkey with user verification included), so
// a password alone cannot refresh a multi-factor session.
func (a SessionAttrs) FreshWithin(d time.Duration, now time.Time) bool {
	if d <= 0 || a.primaryAt.IsZero() || now.Sub(a.primaryAt) > d {
		return false
	}
	if hasRole(a.factors, RoleSecond) || multiFactor(a.factors) {
		return !a.secondAt.IsZero() && now.Sub(a.secondAt) <= d
	}
	return true
}

// MustChangePassword reports whether the user must change their password before anything else.
func (a SessionAttrs) MustChangePassword() bool { return a.mustChange }

func (a SessionAttrs) RememberMe() bool { return a.remember }

// ReturnTo returns the validated post-login target, or "".
func (a SessionAttrs) ReturnTo() string { return a.returnTo }

// Transport returns the sealed credential transport.
func (a SessionAttrs) Transport() Transport { return a.transport }

// Provider returns the federation or external provider of the primary factor, or "".
func (a SessionAttrs) Provider() string { return a.provider }

// Epoch returns the subject's security epoch sealed into the session; the session is dead once
// the subject's current epoch differs.
func (a SessionAttrs) Epoch() uint64 { return a.epoch }

// CreatedAt returns when the lineage was admitted; the absolute lifetime counts from it.
func (a SessionAttrs) CreatedAt() time.Time { return a.createdAt }

// ClaimsFetchedAt returns when application claims were last fetched successfully.
func (a SessionAttrs) ClaimsFetchedAt() time.Time { return a.claimsFetchedAt }

func (a SessionAttrs) clone() SessionAttrs {
	c := a
	c.factors = slices.Clone(a.factors)
	c.credentialIDs = cloneCreds(a.credentialIDs)
	return c
}
