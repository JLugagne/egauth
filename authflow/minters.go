package authflow

import (
	"context"
	"net/http"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/tokens"
)

// JWTMinter creates token pairs using tokens.Issuer and writes auth cookies.
type JWTMinter[C any] struct {
	issuer         tokens.Issuer[C]
	claimsOf       identity.ClaimsBuilder[C]
	cookies        tokens.Cookies
	persistRefresh bool
}

// NewJWTMinter creates a SessionMinter that mints JWT access/refresh token pairs and sets auth cookies.
func NewJWTMinter[C any](
	issuer tokens.Issuer[C],
	claimsOf identity.ClaimsBuilder[C],
	cookies tokens.Cookies,
	persistRefresh bool,
) *JWTMinter[C] {
	return &JWTMinter[C]{
		issuer:         issuer,
		claimsOf:       claimsOf,
		cookies:        cookies,
		persistRefresh: persistRefresh,
	}
}

// Mint issues a JWT token pair and writes the access and refresh cookies.
func (m *JWTMinter[C]) Mint(ctx context.Context, w http.ResponseWriter, r *http.Request, flow *FlowContext) error {
	user := &identity.User{
		ID:       flow.UserID,
		TenantID: flow.TenantID,
		Email:    flow.UserEmail,
	}
	claims := m.claimsOf(user)
	claims.TenantID = flow.TenantID
	claims.Subject = flow.UserID
	claims.AMR = append([]string{}, flow.AMR...)
	claims.MustChangePassword = flow.MustChangePassword

	pair, err := m.issuer.IssueTokenPair(ctx, claims)
	if err != nil {
		return err
	}

	if w != nil {
		m.cookies.SetAccess(w, pair.AccessToken)
		m.cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, m.persistRefresh || flow.RememberMe)
	}
	return nil
}

// StatefulSessionMinter creates stateful sessions using sessions.Service.
type StatefulSessionMinter struct {
	svc        sessions.Service
	cookieName string
	duration   time.Duration
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
		http.SetCookie(w, &http.Cookie{
			Name:     m.cookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   r != nil && r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(m.duration.Seconds()),
		})
	}
	return nil
}
