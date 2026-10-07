package core

import (
	"bytes"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
)

// Admit turns a bound Pending into a session, or asks for a second factor (DESIGN §4.3). It
// requires an unexpired login Pending with a primary factor, a usable account whose epoch is the
// epoch at bind, and, when mfa requires a factor, a multi-factor set; otherwise the Admission
// carries NeedsFactor. The account's must-change flag is taken from st, never from the caller
// (I-12). Errors: ErrPendingExpired, ErrNotBound, ErrReauthPending, ErrNoPrimary,
// ErrAccountUnusable, ErrEpochStale, ErrInvalidArgument (also for the zero MFADecision and a
// Pending without a valid transport).
func Admit(p Pending, st AccountState, mfa MFADecision, now time.Time) (Admission, error) {
	if p.version == 0 || !p.transport.Valid() || mfa.IsZero() || now.IsZero() {
		return Admission{}, ErrInvalidArgument
	}
	if !now.Before(p.expiresAt) {
		return Admission{}, ErrPendingExpired
	}
	if !p.Bound() {
		return Admission{}, ErrNotBound
	}
	if p.reauthOf != uuid.Nil {
		return Admission{}, ErrReauthPending
	}
	fs := p.factorSet()
	if !hasRole(fs, RolePrimary) {
		return Admission{}, ErrNoPrimary
	}
	if !st.Usable() {
		return Admission{}, ErrAccountUnusable
	}
	if st.epoch != p.epochAtBind {
		return Admission{}, ErrEpochStale
	}
	if mfa.Required() && !multiFactor(fs) {
		return Admission{pending: p.clone(), needs: mfa.Factors()}, nil
	}
	now = canonTime(now)
	a := SessionAttrs{
		version:         codecVersion,
		lineage:         uuid.New(),
		subject:         p.subject,
		factors:         fs,
		credentialIDs:   p.credentialUses(),
		primaryAt:       p.primaryAt(),
		secondAt:        p.secondAt(),
		epoch:           st.epoch,
		mustChange:      st.mustChange,
		remember:        p.remember,
		returnTo:        p.returnTo,
		transport:       p.transport,
		provider:        p.provider,
		createdAt:       now,
		claimsFetchedAt: now,
	}
	return Admission{attrs: a, session: true}, nil
}

// Reauthenticate refreshes the freshness of session a from a Pending created by PendingForReauth
// for the same lineage. The lineage is kept; factors are only added; primaryAt is refreshed, and
// secondAt only when the Pending verified a second factor or a passkey with user verification, so
// a password alone never makes a multi-factor session fresh (C-44). Errors: ErrLineageMismatch,
// ErrSubjectMismatch, ErrPendingExpired, ErrNoPrimary, ErrAccountUnusable, ErrEpochStale,
// ErrFactorRequired, ErrInvalidArgument (also for the zero MFADecision).
func Reauthenticate(a SessionAttrs, p Pending, st AccountState, mfa MFADecision, now time.Time) (SessionAttrs, error) {
	if a.version == 0 || p.version == 0 || mfa.IsZero() || now.IsZero() {
		return SessionAttrs{}, ErrInvalidArgument
	}
	if p.reauthOf == uuid.Nil || p.reauthOf != a.lineage {
		return SessionAttrs{}, ErrLineageMismatch
	}
	if p.subject != a.subject {
		return SessionAttrs{}, ErrSubjectMismatch
	}
	if !now.Before(p.expiresAt) {
		return SessionAttrs{}, ErrPendingExpired
	}
	fs := p.factorSet()
	if !hasRole(fs, RolePrimary) {
		return SessionAttrs{}, ErrNoPrimary
	}
	if !st.Usable() {
		return SessionAttrs{}, ErrAccountUnusable
	}
	if st.epoch != a.epoch || st.epoch != p.epochAtBind {
		return SessionAttrs{}, ErrEpochStale
	}
	if mfa.Required() && !multiFactor(fs) {
		return SessionAttrs{}, ErrFactorRequired
	}
	n := a.clone()
	n.factors = unionFactors(a.factors, fs)
	for _, u := range p.credentialUses() {
		if !slices.ContainsFunc(n.credentialIDs, func(e credentialUse) bool {
			return e.factor == u.factor && bytes.Equal(e.id, u.id)
		}) {
			n.credentialIDs = append(n.credentialIDs, u)
		}
	}
	n.primaryAt = p.primaryAt()
	if s := p.secondAt(); !s.IsZero() {
		n.secondAt = s
	}
	n.mustChange = a.mustChange || st.mustChange
	return n, nil
}

// FactorEnrolled records that session a enrolled the second factor f. st must carry the epoch
// bumped by the enrollment, exactly one above a's (ErrEpochStale otherwise), and the result is
// stamped with it. secondAt is left unchanged, so the enrolling session is not fresh for
// sensitive actions until it verifies the new factor (C-45). Errors: ErrInvalidFactor for a
// factor that is not a second factor, ErrAccountUnusable, ErrEpochStale, ErrInvalidArgument.
func FactorEnrolled(a SessionAttrs, f Factor, st AccountState) (SessionAttrs, error) {
	if a.version == 0 {
		return SessionAttrs{}, ErrInvalidArgument
	}
	if f.Role() != RoleSecond {
		return SessionAttrs{}, ErrInvalidFactor
	}
	if err := checkBumped(a, st); err != nil {
		return SessionAttrs{}, err
	}
	n := a.clone()
	n.factors = unionFactors(a.factors, []Factor{f})
	n.epoch = st.epoch
	n.mustChange = a.mustChange || st.mustChange
	return n, nil
}

// PasswordChanged records that session a just changed its password. It adds pwd, refreshes
// primaryAt, clears must-change, keeps every other factor and the lineage (I-19), and stamps st's
// epoch, which must be the epoch bumped by the change: exactly one above a's (ErrEpochStale
// otherwise). Errors: ErrAccountUnusable, ErrEpochStale, ErrInvalidArgument.
func PasswordChanged(a SessionAttrs, st AccountState, now time.Time) (SessionAttrs, error) {
	if a.version == 0 || now.IsZero() {
		return SessionAttrs{}, ErrInvalidArgument
	}
	if err := checkBumped(a, st); err != nil {
		return SessionAttrs{}, err
	}
	n := a.clone()
	n.factors = unionFactors(a.factors, []Factor{FactorPassword})
	n.primaryAt = canonTime(now)
	n.mustChange = false
	n.epoch = st.epoch
	return n, nil
}

// Renew re-validates session a against the authoritative state at rotation. It never adds a
// factor and never touches freshness (T-08); it ORs the account's must-change flag and applies
// the claims outcome. Errors: ErrAccountUnusable, ErrEpochStale (the sealed epoch is not the
// current one), ErrReauthRequired (MFA is required and the session is not multi-factor),
// ErrClaimsUnavailable, ErrClaimsSubjectUnknown, ErrClaimsTooLarge, ErrInvalidArgument (also for
// the zero MFADecision).
func Renew(a SessionAttrs, st AccountState, mfa MFADecision, claims ClaimsOutcome, now time.Time) (SessionAttrs, error) {
	if a.version == 0 || mfa.IsZero() || now.IsZero() {
		return SessionAttrs{}, ErrInvalidArgument
	}
	if !st.Usable() {
		return SessionAttrs{}, ErrAccountUnusable
	}
	if a.epoch != st.epoch {
		return SessionAttrs{}, ErrEpochStale
	}
	if mfa.Required() && !multiFactor(a.factors) {
		return SessionAttrs{}, ErrReauthRequired
	}
	n := a.clone()
	switch claims {
	case ClaimsRefreshed:
		n.claimsFetchedAt = canonTime(now)
	case ClaimsKeptStale:
	case ClaimsUnavailable:
		return SessionAttrs{}, ErrClaimsUnavailable
	case ClaimsSubjectUnknown:
		return SessionAttrs{}, ErrClaimsSubjectUnknown
	case ClaimsTooLarge:
		return SessionAttrs{}, ErrClaimsTooLarge
	default:
		return SessionAttrs{}, errors.Join(ErrInvalidArgument, errors.New("claims outcome"))
	}
	n.mustChange = a.mustChange || st.mustChange
	return n, nil
}

func checkBumped(a SessionAttrs, st AccountState) error {
	if !st.Usable() {
		return ErrAccountUnusable
	}
	if st.epoch != a.epoch+1 {
		return ErrEpochStale
	}
	return nil
}
