package egauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/principalctx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
)

type sessionGate[C any] struct {
	a        *Auth[C]
	optional bool
	spec     routes.SessionSpec
	h        PrincipalHandler[C]
}

type refusal struct {
	status    int
	code      string
	anonymous bool
	clear     bool
	discard   bool
}

var (
	refuseNoCredential = refusal{status: http.StatusUnauthorized, code: codeUnauthenticated, anonymous: true}
	refuseUnavailable  = refusal{status: http.StatusServiceUnavailable, code: codeUnavailable, anonymous: true, discard: true}
	refuseMustChange   = refusal{status: http.StatusForbidden, code: codeMustChange, anonymous: true}
	refuseRequirement  = refusal{status: http.StatusForbidden, code: codeForbidden, anonymous: true}
	refuseMismatch     = refusal{status: http.StatusUnauthorized, code: codeUnauthenticated, anonymous: true, discard: true}
	refuseAmbiguous    = refusal{status: http.StatusUnauthorized, code: codeUnauthenticated, anonymous: true, discard: true}
)

func withPrincipal[P any](r *http.Request, p P) *http.Request {
	return r.WithContext(principalctx.Set(r.Context(), p))
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func (g *sessionGate[C]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	o := g.a.owned
	tenant, err := o.preamble.Tenant(r)
	if err != nil {
		refuse(w, http.StatusUnauthorized, codeUnauthenticated)
		return
	}
	if g.a.cfg.Insecure.NoOriginCheck == nil {
		pol := csrf.Policy{Origins: o.trusted.For(tenant), Authenticated: true, BearerTransport: !cookie.Present(r) && csrf.BearerAuthorization(r)}
		if err := csrf.Check(r, pol); err != nil {
			if g.optional && safeMethod(r.Method) {
				g.h(w, withPrincipal(r, Principal[C]{}), Principal[C]{})
				return
			}
			refuse(w, http.StatusForbidden, codeCrossSite)
			return
		}
	}
	p, ref := g.authenticate(w, r, tenant)
	if ref.status != 0 {
		if ref.discard {
			discardCredentials(w)
		}
		if ref.clear {
			g.a.clearSession(w)
		}
		if !g.optional || !ref.anonymous {
			refuse(w, ref.status, ref.code)
			return
		}
		p = Principal[C]{}
	}
	g.h(w, withPrincipal(r, p), p)
}

func (a *Auth[C]) clearSession(w http.ResponseWriter) {
	pol := a.owned.cookies
	for _, n := range []cookie.Name{cookie.AccessToken, cookie.RefreshToken, cookie.StatefulSession} {
		pol.Clear(w, n)
	}
}

func (a *Auth[C]) sessionCookie(r *http.Request) bool {
	pol := a.owned.cookies
	for _, n := range []cookie.Name{cookie.AccessToken, cookie.RefreshToken, cookie.StatefulSession} {
		if _, ok := pol.Read(r, n); ok {
			return true
		}
	}
	return false
}

func (g *sessionGate[C]) authenticate(w http.ResponseWriter, r *http.Request, tenant core.TenantID) (Principal[C], refusal) {
	o := g.a.owned
	fromCookie := g.a.sessionCookie(r)
	bearer := bearerPresented(r)
	switch {
	case !fromCookie && !bearer:
		return Principal[C]{}, refuseNoCredential
	case fromCookie && bearer:
		return Principal[C]{}, refuseAmbiguous
	}
	if !fromCookie && g.optional && g.a.apiKeyLike(r) {
		return Principal[C]{}, refuseNoCredential
	}
	res, err := o.backend.Resume(r.Context(), w, r, tenant)
	switch {
	case errors.Is(err, httpx.ErrUnavailable):
		return Principal[C]{}, refuseUnavailable
	case errors.Is(err, session.ErrTenantMismatch):
		return Principal[C]{}, refuseMismatch
	case err != nil:
		return Principal[C]{}, refusal{status: http.StatusUnauthorized, code: codeUnauthenticated, anonymous: fromCookie, clear: fromCookie, discard: true}
	}
	a := res.Attrs()
	if a.IsZero() || a.Subject().IsZero() || a.Subject().Tenant != tenant {
		return Principal[C]{}, refuseMismatch
	}
	if !fromCookie && a.Transport() != core.TransportBearer {
		return Principal[C]{}, refuseMismatch
	}
	claims, err := decodeClaims[C](res.Claims().Bytes())
	if err != nil {
		return Principal[C]{}, refuseMismatch
	}
	switch err := g.spec.Check(a, routes.Claims{Roles: claims.Roles, Scopes: claims.Scopes, Groups: claims.Groups}, o.clock.Now()); {
	case errors.Is(err, routes.ErrMustChange):
		return Principal[C]{}, refuseMustChange
	case err != nil:
		return Principal[C]{}, refuseRequirement
	}
	p, err := sessionPrincipal(a, claims)
	if err != nil {
		return Principal[C]{}, refuseMismatch
	}
	return p, refusal{}
}

func decodeClaims[C any](b []byte) (AppClaims[C], error) {
	if len(b) == 0 {
		return AppClaims[C]{}, nil
	}
	var wire claimsWire[C]
	if err := json.Unmarshal(b, &wire); err != nil {
		return AppClaims[C]{}, errors.Join(errors.New("egauth: sealed application claims do not decode"), err)
	}
	return AppClaims[C](wire), nil
}

func (a *Auth[C]) apiKeyLike(r *http.Request) bool {
	m := a.cfg.Modules.APIKeys
	if m == nil {
		return false
	}
	tok, ok := bearerCredential(r)
	return ok && strings.HasPrefix(tok, m.Prefix+apiKeySeparator)
}

func bearerPresented(r *http.Request) bool {
	for _, v := range r.Header.Values("Authorization") {
		scheme, _, _ := strings.Cut(strings.TrimSpace(v), " ")
		if strings.EqualFold(scheme, "bearer") {
			return true
		}
	}
	return false
}

func bearerCredential(r *http.Request) (string, bool) {
	vs := r.Header.Values("Authorization")
	if len(vs) != 1 {
		return "", false
	}
	scheme, tok, ok := strings.Cut(strings.TrimSpace(vs[0]), " ")
	tok = strings.TrimSpace(tok)
	if !ok || !strings.EqualFold(scheme, "bearer") || tok == "" || strings.ContainsAny(tok, " \t") {
		return "", false
	}
	return tok, true
}
