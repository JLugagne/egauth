// Package stateful is the stateful session backend of DESIGN §3.10: a session is one sessions.Store
// row holding the sealed attributes and application claims, read on every request.
package stateful

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/sessions"
)

var _ session.Backend = (*Backend)(nil)

var (
	// ErrInvalidConfig reports a backend configuration that cannot work.
	ErrInvalidConfig = errors.New("stateful: invalid configuration")
	// ErrNoCredential reports a request that presents no session token.
	ErrNoCredential = errors.New("stateful: no session credential")
	// ErrInvalidToken reports a session token that is malformed or names no live session.
	ErrInvalidToken = errors.New("stateful: invalid session token")
	// ErrTransportMismatch reports a token presented on another transport than the one sealed in its
	// session: a cookie session over Authorization, or a Bearer session in a cookie.
	ErrTransportMismatch = errors.New("stateful: credential presented on another transport than its sealed one")
	// ErrAmbiguousTransport reports a request carrying a session cookie and a Bearer credential
	// together; neither is chosen.
	ErrAmbiguousTransport = errors.New("stateful: session cookie and Bearer credential presented together")
	// ErrLifetimeExceeded reports a session past its absolute lifetime.
	ErrLifetimeExceeded = errors.New("stateful: session past its absolute lifetime")
	// ErrCorrupt reports a session row whose index fields disagree with its sealed attributes.
	ErrCorrupt = errors.New("stateful: session row disagrees with its sealed session")
)

// Config configures New; every field but Clock and Events is required. Epochs is the process-wide
// epoch cache whose poller the composition runs. The zero Clock reads the wall clock.
type Config struct {
	Sessions sessions.Store
	Epochs   *revoke.Epochs
	Renewer  *session.Renewer
	Cookies  cookie.Policy
	Clock    clock.Clock
	Events   event.Sink
}

// Backend is the stateful session backend. The session token is an opaque random handle; only its
// SHA-256 digest is stored. The row is read on every request, so an ended session is refused at
// once; the subject's epoch is checked through revoke.Epochs, the idle expiry is extended on every
// request and the session is renewed through the Renewer once RecheckEvery has passed since its
// last check. The token survives renewal and changes only on Reissue. It is safe for concurrent use.
type Backend struct {
	sessions sessions.Store
	epochs   *revoke.Epochs
	renewer  *session.Renewer
	cookies  cookie.Policy
	life     session.Lifetimes
	clk      clock.Clock
	events   event.Sink
}

// New returns ErrInvalidConfig for a missing dependency or a zero cookie policy.
func New(cfg Config) (*Backend, error) {
	if cfg.Sessions == nil || cfg.Epochs == nil || cfg.Renewer == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("stateful: sessions store, epoch cache and renewer are required"))
	}
	if cfg.Cookies == (cookie.Policy{}) {
		return nil, errors.Join(ErrInvalidConfig, errors.New("stateful: a cookie policy is required"))
	}
	return &Backend{
		sessions: cfg.Sessions, epochs: cfg.Epochs, renewer: cfg.Renewer, cookies: cfg.Cookies,
		life: cfg.Renewer.Lifetimes(), clk: cfg.Clock, events: cfg.Events,
	}, nil
}

// Durability is the sessions store's.
func (b *Backend) Durability() store.Durability { return b.sessions.Durability() }

func unavailable(err error) error {
	if errors.Is(err, httpx.ErrUnavailable) {
		return err
	}
	return errors.Join(httpx.ErrUnavailable, err)
}

func classifyRevoke(err error) error {
	if errors.Is(err, revoke.ErrUnavailable) {
		return unavailable(err)
	}
	return err
}

func checkStartable(a core.SessionAttrs) error {
	if a.IsZero() || a.Subject().IsZero() || a.Subject().User == uuid.Nil || !a.Transport().Valid() {
		return errors.Join(core.ErrInvalidArgument, errors.New("stateful: session attributes"))
	}
	return nil
}

type row struct {
	id     uuid.UUID
	hash   []byte
	attrs  core.SessionAttrs
	claims core.SealedClaims
	maxAge time.Duration
	now    time.Time
}

func (b *Backend) record(r row) (sessions.Record, error) {
	rec, err := sessions.NewRecord(sessions.Spec{
		ID: r.id, TokenHash: r.hash, Attrs: r.attrs, AppClaims: r.claims.Bytes(),
		IdleTTL: b.life.IdleTimeout, MaxLifetime: r.maxAge, Now: r.now,
	}, core.Seal)
	if errors.Is(err, sessions.ErrLifetimeExceeded) {
		return sessions.Record{}, errors.Join(ErrLifetimeExceeded, err)
	}
	return rec, err
}

// Start creates a session row for a with claims c and writes its token on w, on a's sealed
// transport. Attributes without a subject are refused with core.ErrInvalidArgument: an anonymous
// session cannot be represented (T-16). Claims that are not a compact JSON object of at most
// session.MaxAppClaimsBytes return core.ErrClaimsTooLarge (event ClaimsTooLarge) and nothing is
// stored. A store failure is joined with httpx.ErrUnavailable.
func (b *Backend) Start(ctx context.Context, w http.ResponseWriter, a core.SessionAttrs, c core.SealedClaims) error {
	if err := checkStartable(a); err != nil {
		return err
	}
	claims, err := session.CompactClaims(c.Bytes())
	if err != nil {
		if errors.Is(err, core.ErrClaimsTooLarge) {
			b.emit(ctx, event.ClaimsTooLarge, a.Subject(), "start", err)
		}
		return err
	}
	tok, hash, err := newToken(a.Subject().Tenant)
	if err != nil {
		return err
	}
	rec, err := b.record(row{id: uuid.New(), hash: hash, attrs: a, claims: claims, maxAge: b.life.MaxLifetime, now: b.clk.Now()})
	if err != nil {
		return err
	}
	if err := b.sessions.Create(ctx, rec); err != nil {
		return unavailable(err)
	}
	return b.write(w, a, tok, rec.IdleExpiresAt(), true)
}

// Reissue atomically replaces the row cur with a new row and a new token for a, which must keep
// cur's subject and lineage (session.ErrHandleMismatch otherwise), with claims fetched afresh
// through the Renewer. It returns store.ErrConflict, and writes nothing, once cur is no longer
// live. A claims source that no longer knows the subject revokes cur and returns
// core.ErrClaimsSubjectUnknown (DESIGN §4.4).
func (b *Backend) Reissue(ctx context.Context, w http.ResponseWriter, cur session.Handle, a core.SessionAttrs) error {
	if err := checkStartable(a); err != nil {
		return err
	}
	if cur.IsZero() || cur.Subject() != a.Subject() || cur.Lineage() != a.Lineage() {
		return session.ErrHandleMismatch
	}
	claims, err := b.renewer.FetchClaims(ctx, a.Subject())
	switch {
	case errors.Is(err, core.ErrClaimsSubjectUnknown):
		return b.revokeUnknown(ctx, a.Subject(), cur.ID(), err)
	case err != nil:
		return unavailable(err)
	}
	tok, hash, err := newToken(a.Subject().Tenant)
	if err != nil {
		return err
	}
	rec, err := b.record(row{id: uuid.New(), hash: hash, attrs: a, claims: claims, maxAge: b.life.MaxLifetime, now: b.clk.Now()})
	if err != nil {
		return err
	}
	if err := b.sessions.Replace(ctx, sessions.ReplaceRequest{Previous: cur.ID(), Next: rec}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return err
		}
		return unavailable(err)
	}
	return b.write(w, a, tok, rec.IdleExpiresAt(), true)
}

type loaded struct {
	rec   sessions.Record
	attrs core.SessionAttrs
	hash  []byte
	end   time.Time
}

func (b *Backend) load(ctx context.Context, tok string) (loaded, error) {
	t, hash, err := parseToken(tok)
	if err != nil {
		return loaded{}, errors.Join(ErrInvalidToken, err)
	}
	rec, err := b.sessions.Get(ctx, t, hash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return loaded{}, errors.Join(ErrInvalidToken, err)
	case err != nil:
		return loaded{}, unavailable(err)
	}
	a, err := core.Unseal(rec.Sealed())
	if err != nil {
		return loaded{}, errors.Join(ErrCorrupt, err)
	}
	if rec.Subject() != a.Subject() || rec.Lineage() != a.Lineage() || rec.Epoch() != a.Epoch() || rec.Tenant() != t || a.Subject().User == uuid.Nil {
		return loaded{}, ErrCorrupt
	}
	end := a.CreatedAt().Add(b.life.MaxLifetime)
	if rec.AbsoluteExpiresAt().Before(end) {
		end = rec.AbsoluteExpiresAt()
	}
	return loaded{rec: rec, attrs: a, hash: hash, end: end}, nil
}

// Resume authenticates r (DESIGN §3.10): it reads the session row of the presented token, checks
// the transport sealed in it, the absolute lifetime and the subject's current epoch through the
// epoch cache. Once RecheckEvery has passed since the row's last check it renews the session
// through the Renewer and rewrites the row in place; otherwise it extends the idle expiry. A cookie
// session's cookie is rewritten on every extension, with Max-Age = min(idle, absolute remaining)
// when remembered and as a browser-session cookie otherwise (C-21). The transport is cookies when r
// carries a readable session cookie (exactly one, non-empty), Bearer otherwise; a session cookie
// beside a Bearer credential is refused (ErrAmbiguousTransport). Errors joined with
// httpx.ErrUnavailable are outages (503); every other error refuses the request (401) and nothing
// is written on w. A token sealed for another tenant than tenant returns session.ErrTenantMismatch
// before the row is touched or renewed.
func (b *Backend) Resume(ctx context.Context, w http.ResponseWriter, r *http.Request, tenant core.TenantID) (session.Resumed, error) {
	p := b.read(r)
	if p.ambiguous {
		return session.Resumed{}, ErrAmbiguousTransport
	}
	if p.token == "" {
		return session.Resumed{}, ErrNoCredential
	}
	l, err := b.load(ctx, p.token)
	if err != nil {
		return session.Resumed{}, err
	}
	a := l.attrs
	if l.rec.Tenant() != tenant || a.Subject().Tenant != tenant {
		return session.Resumed{}, session.ErrTenantMismatch
	}
	if a.Transport() != p.transport {
		return session.Resumed{}, ErrTransportMismatch
	}
	now := b.clk.Now()
	if !now.Before(l.end) {
		return session.Resumed{}, ErrLifetimeExceeded
	}
	if err := b.epochs.Check(ctx, a.Subject(), a.Epoch()); err != nil {
		return session.Resumed{}, classifyRevoke(err)
	}
	if now.Sub(l.rec.CheckedAt()) >= b.life.RecheckEvery {
		return b.renew(ctx, w, p.token, l, now)
	}
	idle, err := b.sessions.Touch(ctx, a.Subject().Tenant, l.hash, now.Add(b.life.IdleTimeout))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return session.Resumed{}, errors.Join(ErrInvalidToken, err)
	case err != nil:
		return session.Resumed{}, unavailable(err)
	}
	if err := b.write(w, a, p.token, idle, false); err != nil {
		return session.Resumed{}, err
	}
	return resumed(a, core.NewSealedClaims(l.rec.AppClaims()), l.rec.ID())
}

func (b *Backend) renew(ctx context.Context, w http.ResponseWriter, tok string, l loaded, now time.Time) (session.Resumed, error) {
	a := l.attrs
	renewed, claims, err := b.renewer.Renew(ctx, a, core.NewSealedClaims(l.rec.AppClaims()))
	switch {
	case errors.Is(err, core.ErrClaimsSubjectUnknown):
		return session.Resumed{}, b.revokeUnknown(ctx, a.Subject(), l.rec.ID(), err)
	case errors.Is(err, core.ErrClaimsUnavailable), errors.Is(err, core.ErrClaimsTooLarge):
		return session.Resumed{}, unavailable(err)
	case err != nil:
		return session.Resumed{}, err
	}
	next, err := b.record(row{id: l.rec.ID(), hash: l.hash, attrs: renewed, claims: claims, maxAge: l.end.Sub(a.CreatedAt()), now: now})
	if err != nil {
		return session.Resumed{}, err
	}
	err = b.sessions.Rotate(ctx, sessions.RotateRequest{Previous: l.hash, Next: next})
	switch {
	case errors.Is(err, store.ErrConflict):
		return session.Resumed{}, errors.Join(ErrInvalidToken, err)
	case err != nil:
		return session.Resumed{}, unavailable(err)
	}
	if err := b.write(w, renewed, tok, next.IdleExpiresAt(), false); err != nil {
		return session.Resumed{}, err
	}
	return resumed(renewed, claims, l.rec.ID())
}

func resumed(a core.SessionAttrs, c core.SealedClaims, id uuid.UUID) (session.Resumed, error) {
	h, err := session.NewHandle(a, id)
	if err != nil {
		return session.Resumed{}, err
	}
	return session.NewResumed(a, c, h)
}

func (b *Backend) revokeUnknown(ctx context.Context, s core.Subject, id uuid.UUID, cause error) error {
	if err := b.sessions.RevokeSession(ctx, s, id); err != nil {
		return unavailable(errors.Join(cause, err))
	}
	b.emit(ctx, event.Logout, s, "claims_subject_unknown", cause)
	return cause
}

// End revokes every session token r presents, on either transport, and clears the session cookie
// on w whenever r carries a cookie. It is idempotent: an absent, malformed, unknown or ended token
// only clears. A store failure is joined with httpx.ErrUnavailable.
func (b *Backend) End(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	p := b.read(r)
	if p.transport == core.TransportCookies || cookie.Present(r) {
		b.cookies.Clear(w, cookie.StatefulSession)
	}
	var errs []error
	for _, tok := range p.presented() {
		t, hash, err := parseToken(tok)
		if err != nil {
			continue
		}
		if err := b.sessions.Revoke(ctx, t, hash); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return unavailable(errors.Join(errs...))
	}
	return nil
}

func (b *Backend) emit(ctx context.Context, t event.Type, s core.Subject, reason string, cause error) {
	_ = audit.Emit(ctx, b.events, t, audit.Scope{TenantID: s.Tenant.String(), UserID: s.User.String()}, audit.Detail{Reason: reason}, cause)
}
