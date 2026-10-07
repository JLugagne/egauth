package core

import (
	"slices"
	"time"
)

// Transport is the channel a session's credentials travel on. It is chosen once, at NewPending,
// and sealed; every later step uses the sealed value. The zero Transport is invalid.
type Transport uint8

const (
	// TransportCookies carries credentials in host-only cookies.
	TransportCookies Transport = iota + 1
	// TransportBearer carries credentials in the response body and the Authorization header.
	TransportBearer
)

// Valid reports whether t is TransportCookies or TransportBearer.
func (t Transport) Valid() bool {
	return t == TransportCookies || t == TransportBearer
}

// RememberIntent is what the user asked for on the login form. It only matters under
// RememberUserChoice. The zero RememberIntent is invalid.
type RememberIntent uint8

const (
	// RememberDeclined means the user did not ask to be remembered.
	RememberDeclined RememberIntent = iota + 1
	// RememberRequested means the user asked to be remembered.
	RememberRequested
)

// RememberMePolicy is the deployment's remember-me policy. NewPending is the only function that
// reads it, so it is applied exactly once per journey and sealed (T-19). The zero value is invalid.
type RememberMePolicy uint8

const (
	// RememberUserChoice follows the user's RememberIntent.
	RememberUserChoice RememberMePolicy = iota + 1
	// RememberAlways remembers every session.
	RememberAlways
	// RememberNever remembers no session.
	RememberNever
)

// ClaimsOutcome is the result of the claims-source policy (DESIGN §4.4) handed to Renew. The
// policy itself lives with the caller of Renew; Renew only applies it. The zero value is invalid.
type ClaimsOutcome uint8

const (
	// ClaimsRefreshed means fresh claims were fetched now.
	ClaimsRefreshed ClaimsOutcome = iota + 1
	// ClaimsKeptStale means the source failed within the staleness bound; claims are kept.
	ClaimsKeptStale
	// ClaimsUnavailable means the source failed past the staleness bound.
	ClaimsUnavailable
	// ClaimsSubjectUnknown means the source no longer knows the subject.
	ClaimsSubjectUnknown
	// ClaimsTooLarge means the encoded claims exceed their bound.
	ClaimsTooLarge
)

// AccountState is the authoritative account state read from the identity store. Its zero value
// describes an account that does not exist, so a forgotten load fails closed (I-12).
type AccountState struct {
	exists        bool
	disabled      bool
	deleted       bool
	mustChange    bool
	emailVerified bool
	epoch         uint64
}

// NewAccountState builds the authoritative account state; epoch is the subject's current
// security epoch.
func NewAccountState(exists, disabled, deleted, mustChange, emailVerified bool, epoch uint64) AccountState {
	return AccountState{
		exists:        exists,
		disabled:      disabled,
		deleted:       deleted,
		mustChange:    mustChange,
		emailVerified: emailVerified,
		epoch:         epoch,
	}
}

func (s AccountState) Exists() bool { return s.exists }

func (s AccountState) Disabled() bool { return s.disabled }

func (s AccountState) Deleted() bool { return s.deleted }

func (s AccountState) MustChange() bool { return s.mustChange }

func (s AccountState) EmailVerified() bool { return s.emailVerified }

// Epoch returns the subject's current security epoch.
func (s AccountState) Epoch() uint64 { return s.epoch }

// Usable reports whether the account exists and is neither disabled nor deleted.
func (s AccountState) Usable() bool {
	return s.exists && !s.disabled && !s.deleted
}

// MFADecision states whether a subject must present a second factor, derived from persisted
// enrollment only (D1). The zero value is invalid: Admit, Reauthenticate and Renew refuse it, so a
// forgotten load fails closed like AccountState (I-12).
type MFADecision struct {
	loaded   bool
	enrolled []Factor
}

// NewMFADecision builds the decision from the subject's enrolled second factors; nil or empty
// states explicitly that none is required. Any entry, including an invalid one, makes a factor
// required, so a malformed input fails closed.
func NewMFADecision(enrolled []Factor) MFADecision {
	var out []Factor
	for _, f := range enrolled {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	sortFactors(out)
	return MFADecision{loaded: true, enrolled: out}
}

// IsZero reports whether d was not built by NewMFADecision.
func (d MFADecision) IsZero() bool {
	return !d.loaded
}

// Required reports whether a second factor is required. It is true for the zero MFADecision.
func (d MFADecision) Required() bool {
	return !d.loaded || len(d.enrolled) > 0
}

// Factors returns the enrolled factors that can complete the requirement.
func (d MFADecision) Factors() []Factor {
	return slices.Clone(d.enrolled)
}

// SealedClaims is the encoded application claims sealed next to a session's attributes. Core never
// decodes it.
type SealedClaims struct {
	b []byte
}

// NewSealedClaims copies b.
func NewSealedClaims(b []byte) SealedClaims {
	return SealedClaims{b: slices.Clone(b)}
}

// Bytes returns a copy of the encoded claims.
func (c SealedClaims) Bytes() []byte {
	return slices.Clone(c.b)
}

func (c SealedClaims) Len() int {
	return len(c.b)
}

// Admission is the result of Admit: either a session, or a Pending that needs a second factor.
type Admission struct {
	attrs   SessionAttrs
	pending Pending
	needs   []Factor
	session bool
}

// Session returns the admitted session attributes, and false when a factor is still needed.
func (a Admission) Session() (SessionAttrs, bool) {
	return a.attrs, a.session
}

// NeedsFactor returns the bound Pending to persist as the MFA flow and the factors that can
// complete it, and false when a session was admitted.
func (a Admission) NeedsFactor() (Pending, []Factor, bool) {
	if a.session || a.pending.version == 0 {
		return Pending{}, nil, false
	}
	return a.pending, slices.Clone(a.needs), true
}

func canonTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.Round(0).UTC()
}
