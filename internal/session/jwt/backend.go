package jwt

import (
	"context"
	"errors"
	"net/http"
	"slices"
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
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/tokens"
)

var _ session.Backend = (*Backend)(nil)

var (
	// ErrNoCredential reports a request that presents no session credential.
	ErrNoCredential = errors.New("jwt: no session credential")
	// ErrTransportMismatch reports a credential presented on another transport than the one sealed
	// in its session: a cookie session over Authorization, or a Bearer session in a cookie.
	ErrTransportMismatch = errors.New("jwt: credential presented on another transport than its sealed one")
	// ErrAmbiguousTransport reports a request carrying a session cookie and a Bearer credential
	// together; neither is chosen.
	ErrAmbiguousTransport = errors.New("jwt: session cookie and Bearer credential presented together")
	// ErrLifetimeExceeded reports a session past its absolute lifetime.
	ErrLifetimeExceeded = errors.New("jwt: session past its absolute lifetime")
	// ErrCorrupt reports a refresh record whose index fields disagree with its sealed attributes.
	ErrCorrupt = errors.New("jwt: refresh record disagrees with its sealed session")
	// ErrAudience reports a resource-token audience outside Config.Audiences, or the issuer itself.
	ErrAudience = errors.New("jwt: audience is not one of the resource audiences")
)

// Keys signs and verifies tenant tokens; keys.Manager satisfies it.
type Keys interface {
	KeySource
	Signer(ctx context.Context, t principal.TenantID) (signing.Signer, error)
}

// Config configures New; every field but Audiences, Clock and Events is required. Codec must have
// been built with the Renewer's RecheckEvery. Families and Epochs are the process-wide revocation
// caches; their pollers are run by the composition. Audiences are the resource audiences
// MintResource accepts. The zero Clock reads the wall clock.
type Config struct {
	Codec     *Codec
	Keys      Keys
	Tokens    tokens.Store
	Families  *revoke.Families
	Epochs    *revoke.Epochs
	Renewer   *session.Renewer
	Cookies   cookie.Policy
	Audiences []string
	Clock     clock.Clock
	Events    event.Sink
}

// Backend is the JWT session backend of DESIGN §3.10. A session is a refresh family in
// tokens.Store plus an access token that lives at most RecheckEvery; Resume renews the family
// through tokens.Store.ConsumeForRotation once the access token has expired. It is safe for
// concurrent use.
type Backend struct {
	codec     *Codec
	keys      Keys
	tokens    tokens.Store
	families  *revoke.Families
	epochs    *revoke.Epochs
	renewer   *session.Renewer
	cookies   cookie.Policy
	audiences []string
	life      session.Lifetimes
	clk       clock.Clock
	events    event.Sink
}

// New returns ErrInvalidConfig for a missing dependency, a zero cookie policy or a codec whose
// RecheckEvery differs from the Renewer's.
func New(cfg Config) (*Backend, error) {
	if cfg.Codec == nil || cfg.Keys == nil || cfg.Tokens == nil || cfg.Families == nil || cfg.Epochs == nil || cfg.Renewer == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("jwt: codec, keys, tokens store, revocation caches and renewer are required"))
	}
	if cfg.Cookies == (cookie.Policy{}) {
		return nil, errors.Join(ErrInvalidConfig, errors.New("jwt: a cookie policy is required"))
	}
	life := cfg.Renewer.Lifetimes()
	if cfg.Codec.recheck != life.RecheckEvery {
		return nil, errors.Join(ErrInvalidConfig, errors.New("jwt: codec and renewer disagree on RecheckEvery"))
	}
	for _, aud := range cfg.Audiences {
		if err := checkOrigin(aud); err != nil {
			return nil, errors.Join(ErrInvalidConfig, errors.New("jwt: resource audience "+aud), err)
		}
	}
	return &Backend{
		codec: cfg.Codec, keys: cfg.Keys, tokens: forgetting{Store: cfg.Tokens, families: cfg.Families}, families: cfg.Families, epochs: cfg.Epochs,
		renewer: cfg.Renewer, cookies: cfg.Cookies, audiences: slices.Clone(cfg.Audiences), life: life,
		clk: cfg.Clock, events: cfg.Events,
	}, nil
}

// Durability is the tokens store's.
func (b *Backend) Durability() store.Durability { return b.tokens.Durability() }

func unavailable(err error) error {
	if errors.Is(err, httpx.ErrUnavailable) {
		return err
	}
	return errors.Join(httpx.ErrUnavailable, err)
}

func claimsOutage(err error) error {
	if errors.Is(err, core.ErrClaimsTooLarge) {
		return unavailable(err)
	}
	return err
}

func (b *Backend) absoluteEnd(a core.SessionAttrs) time.Time {
	return a.CreatedAt().Add(b.life.MaxLifetime)
}

func (b *Backend) tokenLifetime(a core.SessionAttrs, now time.Time, limit time.Duration) (time.Duration, error) {
	left := b.absoluteEnd(a).Sub(now).Truncate(time.Second)
	if left < time.Second {
		return 0, ErrLifetimeExceeded
	}
	return min(left, limit), nil
}

type issue struct {
	family uuid.UUID
	attrs  core.SessionAttrs
	claims core.SealedClaims
	fp     []byte
	now    time.Time
}

type issued struct {
	access  string
	refresh string
	record  tokens.RefreshRecord
	token   Token
}

func (b *Backend) prepare(ctx context.Context, in issue) (issued, error) {
	life, err := b.tokenLifetime(in.attrs, in.now, b.life.RecheckEvery)
	if err != nil {
		return issued{}, err
	}
	refresh, hash, err := newRefresh(in.attrs.Subject().Tenant)
	if err != nil {
		return issued{}, err
	}
	rec, err := tokens.NewRefreshRecord(tokens.RefreshSpec{
		TokenHash: hash, Family: in.family, Attrs: in.attrs, AppClaims: in.claims.Bytes(),
		ClientFingerprint: in.fp, IdleTTL: b.life.IdleTimeout, MaxLifetime: b.life.MaxLifetime, Now: in.now,
	}, core.Seal)
	if err != nil {
		if errors.Is(err, tokens.ErrLifetimeExceeded) {
			return issued{}, errors.Join(ErrLifetimeExceeded, err)
		}
		return issued{}, err
	}
	s, err := b.keys.Signer(ctx, in.attrs.Subject().Tenant)
	if err != nil {
		return issued{}, unavailable(err)
	}
	access, tok, err := b.codec.encode(s, mint{family: in.family, issuedAt: in.now, lifetime: life, attrs: in.attrs, claims: in.claims})
	if err != nil {
		return issued{}, err
	}
	if err := b.fits(in.attrs, access, refresh); err != nil {
		b.emit(ctx, event.ClaimsTooLarge, in.attrs.Subject(), "cookie_size", err)
		return issued{}, err
	}
	return issued{access: access, refresh: refresh, record: rec, token: tok}, nil
}

func checkStartable(a core.SessionAttrs) error {
	if a.IsZero() || a.Subject().IsZero() || !a.Transport().Valid() {
		return errors.Join(core.ErrInvalidArgument, errors.New("jwt: session attributes"))
	}
	return nil
}

// Start creates a refresh family for a with claims c and writes its credentials on w, on a's
// sealed transport. Claims that are not a compact JSON object of at most
// session.MaxAppClaimsBytes, or a cookie session that would not fit MaxCookieBytes, return
// core.ErrClaimsTooLarge (event ClaimsTooLarge) and nothing is stored.
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
	out, err := b.prepare(ctx, issue{family: uuid.New(), attrs: a, claims: claims, now: b.clk.Now()})
	if err != nil {
		return err
	}
	if err := b.tokens.Create(ctx, out.record); err != nil {
		return unavailable(err)
	}
	return b.write(w, a, out.access, out.refresh, out.record)
}

// Reissue atomically replaces the family cur with a new family for a, which must keep cur's
// subject and lineage (session.ErrHandleMismatch otherwise), with claims fetched afresh through
// the Renewer. It returns store.ErrConflict, and writes nothing, once cur is no longer live. A
// claims source that no longer knows the subject revokes cur and returns
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
	out, err := b.prepare(ctx, issue{family: uuid.New(), attrs: a, claims: claims, now: b.clk.Now()})
	if err != nil {
		return claimsOutage(err)
	}
	if err := b.tokens.Reissue(ctx, tokens.ReissueRequest{Family: cur.ID(), Next: out.record}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return err
		}
		return unavailable(err)
	}
	return b.write(w, a, out.access, out.refresh, out.record)
}

// Resume authenticates r (DESIGN §3.10): it verifies the access token with its key-pinned
// algorithm, decodes att and apc, checks the transport sealed in it, the absolute lifetime, the
// live family and the subject's current epoch through the revocation caches. Once the access
// token has expired it renews from the refresh token on the same transport through the Renewer
// and ConsumeForRotation, and writes the new credentials on w. A request that loses a rotation
// race to the same client within tokens.ReuseGrace, with the expired access token of that family,
// is served from the renewed attributes and writes nothing. The transport is cookies when r
// carries a readable session cookie (exactly one, non-empty), Bearer otherwise, so unrelated
// cookies never hide a Bearer credential; a session cookie beside a Bearer credential is refused
// (ErrAmbiguousTransport). An access or refresh token sealed for another tenant than tenant
// returns session.ErrTenantMismatch before the refresh token is consumed.
// Errors joined with httpx.ErrUnavailable are outages (503); every other error refuses the request
// (401).
func (b *Backend) Resume(ctx context.Context, w http.ResponseWriter, r *http.Request, tenant core.TenantID) (session.Resumed, error) {
	p := b.read(r)
	if p.ambiguous {
		return session.Resumed{}, ErrAmbiguousTransport
	}
	if p.empty() {
		return session.Resumed{}, ErrNoCredential
	}
	var prior *Token
	if p.access != "" {
		tok, expired, err := b.codec.verify(ctx, p.access, b.keys, "")
		switch {
		case errors.Is(err, httpx.ErrUnavailable):
			return session.Resumed{}, err
		case err != nil && p.refresh == "":
			return session.Resumed{}, err
		case err == nil && tok.attrs.Subject().Tenant != tenant:
			return session.Resumed{}, session.ErrTenantMismatch
		case err == nil && tok.attrs.Transport() != p.transport:
			return session.Resumed{}, ErrTransportMismatch
		case err == nil && !expired:
			return b.resumeLive(ctx, tok)
		case err == nil:
			prior = &tok
		}
	}
	if p.refresh == "" {
		return session.Resumed{}, ErrExpired
	}
	return b.renew(ctx, w, r, p, prior, tenant)
}

func (b *Backend) resumeLive(ctx context.Context, tok Token) (session.Resumed, error) {
	a := tok.attrs
	if !b.clk.Now().Before(b.absoluteEnd(a)) {
		return session.Resumed{}, ErrLifetimeExceeded
	}
	if err := b.families.Live(ctx, a.Subject(), revoke.Family{ID: tok.family, Lineage: a.Lineage()}); err != nil {
		return session.Resumed{}, classifyRevoke(err)
	}
	if err := b.epochs.Check(ctx, a.Subject(), a.Epoch()); err != nil {
		return session.Resumed{}, classifyRevoke(err)
	}
	return resumed(a, tok.claims, tok.family)
}

func classifyRevoke(err error) error {
	if errors.Is(err, revoke.ErrUnavailable) {
		return unavailable(err)
	}
	return err
}

func resumed(a core.SessionAttrs, c core.SealedClaims, family uuid.UUID) (session.Resumed, error) {
	h, err := session.NewHandle(a, family)
	if err != nil {
		return session.Resumed{}, err
	}
	return session.NewResumed(a, c, h)
}

func (b *Backend) load(ctx context.Context, refresh string) (tokens.RefreshRecord, core.SessionAttrs, []byte, error) {
	t, hash, err := parseRefresh(refresh)
	if err != nil {
		return tokens.RefreshRecord{}, core.SessionAttrs{}, nil, err
	}
	rec, err := b.tokens.Get(ctx, t, hash)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, tokens.ErrRevoked):
		return tokens.RefreshRecord{}, core.SessionAttrs{}, nil, err
	case err != nil:
		return tokens.RefreshRecord{}, core.SessionAttrs{}, nil, unavailable(err)
	}
	a, err := core.Unseal(rec.Sealed())
	if err != nil {
		return tokens.RefreshRecord{}, core.SessionAttrs{}, nil, errors.Join(ErrCorrupt, err)
	}
	if rec.Subject() != a.Subject() || rec.Lineage() != a.Lineage() || rec.Epoch() != a.Epoch() || rec.Tenant() != t {
		return tokens.RefreshRecord{}, core.SessionAttrs{}, nil, ErrCorrupt
	}
	return rec, a, hash, nil
}

func (b *Backend) renew(ctx context.Context, w http.ResponseWriter, r *http.Request, p presented, prior *Token, tenant core.TenantID) (session.Resumed, error) {
	rec, a, hash, err := b.load(ctx, p.refresh)
	if err != nil {
		return session.Resumed{}, err
	}
	if rec.Tenant() != tenant || a.Subject().Tenant != tenant {
		return session.Resumed{}, session.ErrTenantMismatch
	}
	if a.Transport() != p.transport {
		return session.Resumed{}, ErrTransportMismatch
	}
	if prior != nil && (prior.family != rec.Family() || prior.attrs.Lineage() != a.Lineage()) {
		return session.Resumed{}, errors.Join(ErrInvalidToken, errors.New("jwt: access and refresh tokens of different sessions"))
	}
	now := b.clk.Now()
	if !now.Before(b.absoluteEnd(a)) {
		return session.Resumed{}, ErrLifetimeExceeded
	}
	renewed, claims, err := b.renewer.Renew(ctx, a, core.NewSealedClaims(rec.AppClaims()))
	switch {
	case errors.Is(err, core.ErrClaimsSubjectUnknown):
		return session.Resumed{}, b.revokeUnknown(ctx, a.Subject(), rec.Family(), err)
	case errors.Is(err, core.ErrClaimsUnavailable), errors.Is(err, core.ErrClaimsTooLarge):
		return session.Resumed{}, unavailable(err)
	case err != nil:
		return session.Resumed{}, err
	}
	out, err := b.prepare(ctx, issue{family: rec.Family(), attrs: renewed, claims: claims, fp: clientFingerprint(r), now: now})
	if err != nil {
		return session.Resumed{}, claimsOutage(err)
	}
	_, err = b.tokens.ConsumeForRotation(ctx, tokens.RotationRequest{Presented: hash, Next: out.record})
	switch {
	case errors.Is(err, tokens.ErrConcurrent) && prior != nil:
		return b.resumeLive(ctx, Token{family: rec.Family(), attrs: renewed, claims: claims})
	case errors.Is(err, tokens.ErrConcurrent):
		return session.Resumed{}, unavailable(err)
	case err != nil:
		return session.Resumed{}, b.rotationFailed(ctx, a.Subject(), err)
	}
	if err := b.write(w, renewed, out.access, out.refresh, out.record); err != nil {
		return session.Resumed{}, err
	}
	return resumed(renewed, out.token.claims, rec.Family())
}

func (b *Backend) rotationFailed(ctx context.Context, s core.Subject, err error) error {
	switch {
	case errors.Is(err, tokens.ErrReused):
		b.emit(ctx, event.RefreshReuseDetected, s, "refresh_reuse", err)
		return err
	case errors.Is(err, tokens.ErrRevoked), errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrConflict):
		return err
	}
	return unavailable(err)
}

func (b *Backend) revokeUnknown(ctx context.Context, s core.Subject, family uuid.UUID, cause error) error {
	if err := b.tokens.RevokeFamily(ctx, s.Tenant, family); err != nil {
		return unavailable(errors.Join(cause, err))
	}
	b.emit(ctx, event.TokenFamilyRevoked, s, "claims_subject_unknown", cause)
	return cause
}

// End revokes the family presented by r, through its refresh token or, failing that, its verified
// access token even if expired, and clears the session cookies on w whenever r carries a cookie.
// It is idempotent: an absent, unknown or revoked credential only clears. A store failure is
// joined with httpx.ErrUnavailable.
func (b *Backend) End(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	p := b.read(r)
	b.clear(w, r, p)
	if p.refresh != "" {
		rec, _, _, err := b.load(ctx, p.refresh)
		switch {
		case err == nil:
			return b.revoke(ctx, rec.Tenant(), rec.Family())
		case errors.Is(err, httpx.ErrUnavailable):
			return err
		}
	}
	if p.access == "" {
		return nil
	}
	tok, _, err := b.codec.verify(ctx, p.access, b.keys, "")
	switch {
	case errors.Is(err, httpx.ErrUnavailable):
		return err
	case err != nil:
		return nil
	}
	return b.revoke(ctx, tok.attrs.Subject().Tenant, tok.family)
}

// Live checks the refresh family h names through the family cache: it must belong to h's subject
// and lineage and be neither revoked nor past its absolute expiry.
func (b *Backend) Live(ctx context.Context, h session.Handle) error {
	if h.IsZero() {
		return session.ErrEnded
	}
	err := b.families.Live(ctx, h.Subject(), revoke.Family{ID: h.ID(), Lineage: h.Lineage()})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, revoke.ErrUnavailable):
		return unavailable(err)
	}
	return errors.Join(session.ErrEnded, err)
}

func (b *Backend) revoke(ctx context.Context, t principal.TenantID, family uuid.UUID) error {
	if err := b.tokens.RevokeFamily(ctx, t, family); err != nil {
		return unavailable(err)
	}
	return nil
}

// MintResource mints a resource token for the resumed session res: the same attributes, claims
// and family, with "aud" set to audience, which must be one of Config.Audiences and never the
// issuer (ErrAudience). It lives lifetime, capped by the session's absolute end; lifetime must be
// between one second and RecheckEvery. The family and epoch are checked again first.
func (b *Backend) MintResource(ctx context.Context, res session.Resumed, audience string, lifetime time.Duration) (string, time.Time, error) {
	a := res.Attrs()
	if a.IsZero() || res.Handle().IsZero() {
		return "", time.Time{}, errors.Join(core.ErrInvalidArgument, errors.New("jwt: resumed session"))
	}
	if lifetime < time.Second || lifetime > b.life.RecheckEvery {
		return "", time.Time{}, errors.Join(core.ErrInvalidArgument, errors.New("jwt: resource token lifetime"))
	}
	iss, err := b.codec.Issuer(a.Subject().Tenant)
	if err != nil {
		return "", time.Time{}, err
	}
	if audience == iss || !slices.Contains(b.audiences, audience) {
		return "", time.Time{}, ErrAudience
	}
	family := res.Handle().ID()
	if _, err := b.resumeLive(ctx, Token{family: family, attrs: a, claims: res.Claims()}); err != nil {
		return "", time.Time{}, err
	}
	now := b.clk.Now()
	life, err := b.tokenLifetime(a, now, lifetime)
	if err != nil {
		return "", time.Time{}, err
	}
	s, err := b.keys.Signer(ctx, a.Subject().Tenant)
	if err != nil {
		return "", time.Time{}, unavailable(err)
	}
	raw, tok, err := b.codec.encode(s, mint{audience: audience, family: family, issuedAt: now, lifetime: life, attrs: a, claims: res.Claims()})
	if err != nil {
		return "", time.Time{}, err
	}
	return raw, tok.expiresAt, nil
}

func (b *Backend) emit(ctx context.Context, t event.Type, s core.Subject, reason string, cause error) {
	_ = audit.Emit(ctx, b.events, t, audit.Scope{TenantID: s.Tenant.String(), UserID: s.User.String()}, audit.Detail{Reason: reason}, cause)
}
