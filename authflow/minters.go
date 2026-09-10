package authflow

import (
	"context"
	"net/http"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/internal/httputil"
	"github.com/JLugagne/egauth/issuance"
	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
)

// JWTMinter creates token pairs using tokens.Issuer and writes auth cookies. Minting goes
// through the unified issuance pipeline, so the forced-change flag the engine accumulated over
// the flow is enforced (never cleared) at issuance, and every flow-minted pair emits the same
// audit event.
type JWTMinter[C any] struct {
	issuer         tokens.Issuer[C]
	claimsOf       identity.ClaimsBuilder[C]
	cookies        tokens.Cookies
	persistRefresh bool
	pipe           *issuance.Pipeline[C]
	pipeErr        error
}

// NewJWTMinter creates a SessionMinter that mints JWT access/refresh token pairs and sets auth cookies.
//
// The engine re-checks the account lifecycle (WithAccountValidator) and resolves the
// forced-password-change flag before it calls Mint, so the pipeline's state source is seeded
// from the completed flow identity; the flow's must-change flag is OR-ed by the pipeline and can
// no longer be dropped by a minter implementation.
func NewJWTMinter[C any](
	issuer tokens.Issuer[C],
	claimsOf identity.ClaimsBuilder[C],
	cookies tokens.Cookies,
	persistRefresh bool,
) *JWTMinter[C] {
	m := &JWTMinter[C]{
		issuer:         issuer,
		claimsOf:       claimsOf,
		cookies:        cookies,
		persistRefresh: persistRefresh,
	}
	pipe, err := issuance.New(issuer, issuance.WithResolver(issuance.ResolverFunc(
		func(_ context.Context, tenantID string, userID uuid.UUID) (issuance.State, error) {
			return issuance.State{UserID: userID, TenantID: tenantID}, nil
		},
	)))
	m.pipe, m.pipeErr = pipe, err
	return m
}

// Mint issues a JWT token pair and writes the access and refresh cookies.
func (m *JWTMinter[C]) Mint(ctx context.Context, w http.ResponseWriter, r *http.Request, flow *FlowContext) error {
	if m.pipeErr != nil {
		return m.pipeErr
	}
	user := &identity.User{
		ID:       flow.UserID,
		TenantID: flow.TenantID,
		Email:    flow.UserEmail,
	}
	res, err := m.pipe.Issue(ctx, issuance.Request[C]{
		TenantID:           flow.TenantID,
		UserID:             flow.UserID,
		Claims:             m.claimsOf(user),
		Method:             flow.PrimaryFactor,
		AMR:                append([]string{}, flow.AMR...),
		MustChangePassword: flow.MustChangePassword,
		// The engine only reaches Mint after account validation and, when MFA is required,
		// after ProcessStepUp completed the second factor; a completed flow is never gated again.
		MFAVerified: true,
	})
	if err != nil {
		return err
	}

	if w != nil {
		m.cookies.SetAccess(w, res.Pair.AccessToken)
		m.cookies.SetRefresh(w, res.Pair.RefreshToken, res.Pair.RefreshTokenExpiresAt, m.persistRefresh || flow.RememberMe)
	}
	return nil
}

// StatefulSessionMinter creates stateful sessions using sessions.Service.
type StatefulSessionMinter struct {
	svc        sessions.Service
	cookieName string
	duration   time.Duration
	// insecureCookies drops the Secure attribute on the session cookie (WithInsecureCookies opt-out, local HTTP dev only). __Host- prefixed names always stay Secure regardless.
	insecureCookies bool
}

// NewStatefulSessionMinter creates a SessionMinter that issues stateful cookie-backed sessions.
func NewStatefulSessionMinter(svc sessions.Service, duration time.Duration, cookieName ...string) *StatefulSessionMinter {
	cName := sessions.DefaultSessionCookieName
	if len(cookieName) > 0 && cookieName[0] != "" {
		cName = cookieName[0]
	}
	if duration <= 0 {
		duration = 24 * time.Hour
	}
	return &StatefulSessionMinter{
		svc:        svc,
		cookieName: cName,
		duration:   duration,
	}
}

// WithInsecureCookies disables the Secure attribute on the session cookie this minter writes.
// Use only for local HTTP development, and only with a cookie name WITHOUT the browser-enforced
// __Host- prefix: the default name (sessions.DefaultSessionCookieName) carries that prefix, and
// for __Host- names Secure is browser-mandatory — it is kept even when this opt-out is set,
// mirroring the tokens.Cookies.Validate() contract. The minter has no event seam, so unlike the
// engine-level WithInsecureCookies it cannot emit the InsecureCookieMisuse warning; configure
// the engine's own opt-out and event sink for that signal. Returns the minter for chaining.
func (m *StatefulSessionMinter) WithInsecureCookies() *StatefulSessionMinter {
	m.insecureCookies = true
	return m
}

// Mint creates a stateful session and writes the session cookie.
func (m *StatefulSessionMinter) Mint(ctx context.Context, w http.ResponseWriter, r *http.Request, flow *FlowContext) error {
	ua := ""
	ip := ""
	if r != nil {
		ua = r.UserAgent()
		ip = r.RemoteAddr
	}

	_, token, err := m.svc.CreateSession(ctx, flow.TenantID, flow.UserID, ua, ip, m.duration)
	if err != nil {
		return err
	}

	if w != nil {
		httputil.MarkNoStore(w)
		http.SetCookie(w, &http.Cookie{
			Name:     m.cookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   !m.insecureCookies || isHostPrefixedCookieName(m.cookieName),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(m.duration.Seconds()),
		})
	}
	return nil
}
