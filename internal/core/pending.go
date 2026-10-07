package core

import (
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/redirect"
)

// PendingTTL bounds how long a Pending can collect factors before Admit refuses it.
const PendingTTL = 15 * time.Minute

const bindHashLen = 32

// Verified is the result of one successful verification ceremony. One verification can yield
// several factors (a passkey assertion yields pk and uv). Only internal/factors builds it.
type Verified struct {
	subject      Subject
	factors      []Factor
	credentialID []byte
	identifies   bool
	provider     string
	at           time.Time
}

// VerifiedSpec describes a verification for NewVerified.
type VerifiedSpec struct {
	Subject Subject
	Factors []Factor
	// CredentialID is the passkey credential used; required for pk and pk_stepup, forbidden
	// otherwise.
	CredentialID []byte
	// Identifies is true when the verification itself resolved the subject, so it may bind an
	// unbound Pending. Second factors never identify.
	Identifies bool
	// Provider names the federation or external provider; required for fed and ext, forbidden
	// otherwise.
	Provider string
	At       time.Time
}

// NewVerified validates s and builds a Verified. Its only allowed caller is internal/factors.
// It returns ErrInvalidVerified unless s is either one second factor alone, or one primary factor
// with uv exactly when that factor is pk.
func NewVerified(s VerifiedSpec) (Verified, error) {
	if s.Subject.IsZero() || s.At.IsZero() {
		return Verified{}, ErrInvalidVerified
	}
	if err := checkVerifiedShape(s.Factors, s.CredentialID, s.Identifies, s.Provider); err != nil {
		return Verified{}, errors.Join(ErrInvalidVerified, err)
	}
	fs := slices.Clone(s.Factors)
	sortFactors(fs)
	return Verified{
		subject:      s.Subject,
		factors:      fs,
		credentialID: cloneBytes(s.CredentialID),
		identifies:   s.Identifies,
		provider:     s.Provider,
		at:           canonTime(s.At),
	}, nil
}

func checkVerifiedShape(fs []Factor, credentialID []byte, identifies bool, provider string) error {
	if len(fs) == 0 {
		return errors.New("no factor")
	}
	var primary, second, uv int
	for i, f := range fs {
		if !f.Valid() || slices.Contains(fs[:i], f) {
			return ErrInvalidFactor
		}
		switch f.Role() {
		case RolePrimary:
			primary++
		case RoleSecond:
			second++
		case RoleQualifier:
			uv++
		}
	}
	hasPK := slices.Contains(fs, FactorPasskey)
	switch {
	case second == 1 && primary == 0 && uv == 0:
		if identifies {
			return errors.New("second factors do not identify")
		}
	case primary == 1 && second == 0 && (uv == 1) == hasPK:
	default:
		return errors.New("invalid factor combination")
	}
	needsCred := hasPK || slices.Contains(fs, FactorPasskeyStepUp)
	if needsCred != (len(credentialID) > 0) {
		return errors.New("credential id mismatch")
	}
	needsProvider := slices.Contains(fs, FactorFederated) || slices.Contains(fs, FactorExternal)
	if needsProvider != (provider != "") {
		return errors.New("provider mismatch")
	}
	return nil
}

func (v Verified) Subject() Subject { return v.subject }

// Factors returns the verified factors, ordered by code.
func (v Verified) Factors() []Factor { return slices.Clone(v.factors) }

// CredentialID returns the passkey credential used, or nil.
func (v Verified) CredentialID() []byte { return slices.Clone(v.credentialID) }

// Identifies reports whether the verification resolved the subject itself.
func (v Verified) Identifies() bool { return v.identifies }

func (v Verified) Provider() string { return v.provider }

func (v Verified) At() time.Time { return v.at }

func (v Verified) clone() Verified {
	c := v
	c.factors = slices.Clone(v.factors)
	c.credentialID = cloneBytes(v.credentialID)
	return c
}

// Pending is the pre-session state of one login or reauthentication journey. It is sealed on the
// ceremony record or stateless handle the next step consumes and replayed from there. It has no
// public alias. The zero value is invalid.
type Pending struct {
	version     uint8
	tenant      TenantID
	subject     Subject
	epochAtBind uint64
	verified    []Verified
	remember    bool
	returnTo    string
	transport   Transport
	provider    string
	reauthOf    uuid.UUID
	bindHash    []byte
	expiresAt   time.Time
}

// NewPending starts a login journey. It is the only place the remember-me policy is applied
// (T-19): the result is sealed and every later step replays it. returnTo is already validated by
// construction. It returns ErrInvalidArgument for a zero or unknown enum.
func NewPending(t TenantID, remember RememberIntent, returnTo redirect.Target, tr Transport, pol RememberMePolicy, now time.Time) (Pending, error) {
	if remember != RememberDeclined && remember != RememberRequested {
		return Pending{}, errors.Join(ErrInvalidArgument, errors.New("remember intent"))
	}
	if !tr.Valid() {
		return Pending{}, errors.Join(ErrInvalidArgument, errors.New("transport"))
	}
	var rem bool
	switch pol {
	case RememberUserChoice:
		rem = remember == RememberRequested
	case RememberAlways:
		rem = true
	case RememberNever:
		rem = false
	default:
		return Pending{}, errors.Join(ErrInvalidArgument, errors.New("remember-me policy"))
	}
	if now.IsZero() {
		return Pending{}, errors.Join(ErrInvalidArgument, errors.New("time"))
	}
	return Pending{
		version:   codecVersion,
		tenant:    t,
		remember:  rem,
		returnTo:  returnTo.String(),
		transport: tr,
		expiresAt: canonTime(now.Add(PendingTTL)),
	}, nil
}

// PendingForReauth starts a reauthentication of the session a. The result is bound to a's
// subject and epoch, keeps a's remember-me and transport, and can only be completed by
// Reauthenticate on the same lineage. For zero attributes it returns the zero Pending, which
// every later step refuses.
func PendingForReauth(a SessionAttrs, now time.Time) Pending {
	if a.version == 0 {
		return Pending{}
	}
	return Pending{
		version:     codecVersion,
		tenant:      a.subject.Tenant,
		subject:     a.subject,
		epochAtBind: a.epoch,
		remember:    a.remember,
		transport:   a.transport,
		reauthOf:    a.lineage,
		expiresAt:   canonTime(now.Add(PendingTTL)),
	}
}

// Bind binds an unbound Pending to s before any factor is verified (username-first ceremonies),
// recording st's epoch. Every later Add must then verify s itself (C-29). It returns
// ErrTenantMismatch, ErrAlreadyBound or ErrInvalidArgument.
func (p Pending) Bind(s Subject, st AccountState) (Pending, error) {
	if p.version == 0 || s.IsZero() {
		return Pending{}, ErrInvalidArgument
	}
	if s.Tenant != p.tenant {
		return Pending{}, ErrTenantMismatch
	}
	if p.Bound() {
		return Pending{}, ErrAlreadyBound
	}
	n := p.clone()
	n.subject = s
	n.epochAtBind = st.epoch
	return n, nil
}

// WithBindHash records the hash of the browser-binding secret. It can be set once; it returns
// ErrInvalidArgument for a hash that is not 32 bytes or when one is already set.
func (p Pending) WithBindHash(h []byte) (Pending, error) {
	if p.version == 0 || len(h) != bindHashLen || len(p.bindHash) != 0 {
		return Pending{}, ErrInvalidArgument
	}
	n := p.clone()
	n.bindHash = cloneBytes(h)
	return n, nil
}

// Add accumulates a verification (DESIGN §4.3, C-28, C-29):
//   - v's tenant must be p's tenant (ErrTenantMismatch);
//   - an unbound Pending is bound only by an identifying primary verification, recording st's
//     epoch (ErrNotBound for a second factor, ErrNotIdentifying otherwise);
//   - a bound Pending accepts only verifications of its subject (ErrSubjectMismatch) while st's
//     epoch is the epoch at bind (ErrEpochStale);
//   - a passkey step-up cannot reuse the primary passkey's credential (ErrSameCredential).
func (p Pending) Add(v Verified, st AccountState) (Pending, error) {
	if p.version == 0 || len(v.factors) == 0 {
		return Pending{}, ErrInvalidArgument
	}
	if v.subject.Tenant != p.tenant {
		return Pending{}, ErrTenantMismatch
	}
	if !v.at.Before(p.expiresAt) {
		return Pending{}, ErrPendingExpired
	}
	n := p.clone()
	if !p.Bound() {
		if hasRole(v.factors, RoleSecond) {
			return Pending{}, ErrNotBound
		}
		if !v.identifies {
			return Pending{}, ErrNotIdentifying
		}
		n.subject = v.subject
		n.epochAtBind = st.epoch
	} else {
		if v.subject != p.subject {
			return Pending{}, ErrSubjectMismatch
		}
		if st.epoch != p.epochAtBind {
			return Pending{}, ErrEpochStale
		}
	}
	creds := p.credentialUses()
	for _, f := range v.factors {
		if credentialClash(creds, f, v.credentialID) {
			return Pending{}, ErrSameCredential
		}
	}
	if v.provider != "" {
		if p.provider != "" && p.provider != v.provider {
			return Pending{}, ErrProviderMismatch
		}
		n.provider = v.provider
	}
	n.verified = append(n.verified, v.clone())
	return n, nil
}

func (p Pending) Tenant() TenantID { return p.tenant }

// Subject returns the bound subject, and false while unbound.
func (p Pending) Subject() (Subject, bool) { return p.subject, p.Bound() }

func (p Pending) Bound() bool { return !p.subject.IsZero() }

// EpochAtBind returns the subject's security epoch recorded when the Pending was bound.
func (p Pending) EpochAtBind() uint64 { return p.epochAtBind }

// Factors returns the union of the verified factors, ordered by code.
func (p Pending) Factors() []Factor { return p.factorSet() }

// MultiFactor applies the SessionAttrs.MultiFactor rule to the verified factors.
func (p Pending) MultiFactor() bool { return multiFactor(p.factorSet()) }

// RememberMe returns the remember-me decision sealed by NewPending.
func (p Pending) RememberMe() bool { return p.remember }

// ReturnTo returns the validated post-login target, or "".
func (p Pending) ReturnTo() string { return p.returnTo }

// Transport returns the sealed credential transport.
func (p Pending) Transport() Transport { return p.transport }

// Provider returns the federation or external provider of the primary factor, or "".
func (p Pending) Provider() string { return p.provider }

// ReauthOf returns the lineage being reauthenticated, and false for a login journey.
func (p Pending) ReauthOf() (uuid.UUID, bool) { return p.reauthOf, p.reauthOf != uuid.Nil }

// BindHash returns the browser-binding hash, or nil.
func (p Pending) BindHash() []byte { return slices.Clone(p.bindHash) }

// ExpiresAt returns the instant from which the Pending is refused.
func (p Pending) ExpiresAt() time.Time { return p.expiresAt }

func (p Pending) clone() Pending {
	c := p
	c.bindHash = cloneBytes(p.bindHash)
	if len(p.verified) > 0 {
		c.verified = make([]Verified, len(p.verified))
		for i, v := range p.verified {
			c.verified[i] = v.clone()
		}
	}
	return c
}

func (p Pending) factorSet() []Factor {
	var out []Factor
	for _, v := range p.verified {
		out = unionFactors(out, v.factors)
	}
	return out
}

func (p Pending) credentialUses() []credentialUse {
	var out []credentialUse
	for _, v := range p.verified {
		if len(v.credentialID) == 0 {
			continue
		}
		for _, f := range v.factors {
			if f == FactorPasskey || f == FactorPasskeyStepUp {
				out = append(out, credentialUse{factor: f, id: cloneBytes(v.credentialID)})
			}
		}
	}
	return out
}

func (p Pending) latest(match func(Verified) bool) time.Time {
	var t time.Time
	for _, v := range p.verified {
		if match(v) && v.at.After(t) {
			t = v.at
		}
	}
	return t
}

func (p Pending) primaryAt() time.Time {
	return p.latest(func(v Verified) bool { return hasRole(v.factors, RolePrimary) })
}

func (p Pending) secondAt() time.Time {
	return p.latest(func(v Verified) bool {
		return hasRole(v.factors, RoleSecond) || multiFactor(v.factors)
	})
}
