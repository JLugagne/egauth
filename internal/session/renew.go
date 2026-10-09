package session

import (
	"context"
	"errors"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
)

// ErrInvalidConfig reports a Renewer or Lifetimes that cannot work: a missing dependency, a
// non-positive lifetime or an idle timeout longer than the absolute lifetime.
var ErrInvalidConfig = errors.New("session: invalid session configuration")

// Lifetimes are the session bounds both backends enforce. IdleTimeout and MaxLifetime bound the
// stored session; RecheckEvery is how often a session is renewed against the authoritative state,
// and the longest an access token lives.
type Lifetimes struct {
	IdleTimeout  time.Duration
	MaxLifetime  time.Duration
	RecheckEvery time.Duration
}

// Validate returns ErrInvalidConfig for a non-positive duration or an IdleTimeout longer than
// MaxLifetime.
func (l Lifetimes) Validate() error {
	if l.IdleTimeout <= 0 || l.MaxLifetime <= 0 || l.RecheckEvery <= 0 {
		return errors.Join(ErrInvalidConfig, errors.New("session: lifetimes must be positive"))
	}
	if l.IdleTimeout > l.MaxLifetime {
		return errors.Join(ErrInvalidConfig, errors.New("session: idle timeout exceeds the absolute lifetime"))
	}
	return nil
}

// Authority answers the authoritative state a session is renewed against. identitysvc produces the
// account state and issuance the MFA decision (G6). An infrastructure failure must be joined with
// httpx.ErrUnavailable so that the request answers 503, never 401 or a renewal.
type Authority interface {
	AccountState(ctx context.Context, s core.Subject) (core.AccountState, error)
	MFADecision(ctx context.Context, s core.Subject) (core.MFADecision, error)
}

// RenewConfig configures NewRenewer. Authority and Claims are required; the zero Clock reads the
// wall clock and a nil Events drops the claims events.
type RenewConfig struct {
	Authority Authority
	Claims    ClaimsSource
	Lifetimes Lifetimes
	Clock     clock.Clock
	Events    event.Sink
}

// Renewer is the only caller of core.Renew: it re-reads the account state, the MFA decision and
// the application claims of a session and applies the claims policy of DESIGN §4.4. Both session
// backends renew through it, so disable, delete, must-change and MFA enrollment are enforced at
// every renewal exactly as at login, with no separate hook to wire (I-10). It is safe for
// concurrent use.
type Renewer struct {
	authority Authority
	claims    ClaimsSource
	life      Lifetimes
	clk       clock.Clock
	events    event.Sink
}

// NewRenewer returns ErrInvalidConfig for a missing Authority or Claims, or invalid Lifetimes.
func NewRenewer(cfg RenewConfig) (*Renewer, error) {
	if cfg.Authority == nil || cfg.Claims == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("session: a renewer needs an authority and a claims source"))
	}
	if err := cfg.Lifetimes.Validate(); err != nil {
		return nil, err
	}
	return &Renewer{authority: cfg.Authority, claims: cfg.Claims, life: cfg.Lifetimes, clk: cfg.Clock, events: cfg.Events}, nil
}

// Lifetimes returns the bounds the Renewer was built with.
func (r *Renewer) Lifetimes() Lifetimes { return r.life }

// Renew re-validates session a, whose current claims are current, and returns the renewed
// attributes and claims. The subject, lineage and factors never change (T-02, T-08); must-change
// only goes from false to true. Claims follow DESIGN §4.4: a source failure keeps current while
// the session's claims are at most RecheckEvery old (event ClaimsStale) and fails with
// core.ErrClaimsUnavailable past that (event ClaimsUnavailable); oversized claims fail with
// core.ErrClaimsTooLarge (event ClaimsTooLarge); ErrUnknownSubject fails with
// core.ErrClaimsSubjectUnknown, on which the caller must revoke the session. Other errors are
// core.ErrAccountUnusable, core.ErrEpochStale, core.ErrReauthRequired and the Authority's own.
func (r *Renewer) Renew(ctx context.Context, a core.SessionAttrs, current core.SealedClaims) (core.SessionAttrs, core.SealedClaims, error) {
	if a.IsZero() {
		return core.SessionAttrs{}, core.SealedClaims{}, core.ErrInvalidArgument
	}
	s := a.Subject()
	st, err := r.authority.AccountState(ctx, s)
	if err != nil {
		return core.SessionAttrs{}, core.SealedClaims{}, errors.Join(errors.New("session: account state"), err)
	}
	mfa, err := r.authority.MFADecision(ctx, s)
	if err != nil {
		return core.SessionAttrs{}, core.SealedClaims{}, errors.Join(errors.New("session: MFA decision"), err)
	}
	now := r.clk.Now()
	outcome, claims, cause := r.renewalClaims(ctx, a, current, now)
	n, err := core.Renew(a, st, mfa, outcome, now)
	switch {
	case errors.Is(err, core.ErrClaimsUnavailable):
		r.emit(ctx, event.ClaimsUnavailable, s, "renewal", cause)
		return core.SessionAttrs{}, core.SealedClaims{}, errors.Join(err, cause)
	case errors.Is(err, core.ErrClaimsTooLarge):
		r.emit(ctx, event.ClaimsTooLarge, s, "renewal", cause)
		return core.SessionAttrs{}, core.SealedClaims{}, errors.Join(err, cause)
	case err != nil:
		return core.SessionAttrs{}, core.SealedClaims{}, err
	}
	if outcome == core.ClaimsKeptStale {
		r.emit(ctx, event.ClaimsStale, s, "renewal", cause)
	}
	return n, claims, nil
}
