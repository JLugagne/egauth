// Package endpoints serves the session endpoints every deployment has, whatever its session
// backend: GET /session and POST /logout, /logout-everywhere and /refresh (DESIGN §3.9). It lives
// below internal/session because internal/httpx, which routes.Endpoint needs, imports
// internal/session.
package endpoints

import (
	"context"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session"
)

// ErrInvalidConfig reports a missing Backend or Audit.
var ErrInvalidConfig = errors.New("endpoints: a session backend and an audit emitter are required")

// Config holds the one session backend of the deployment, which both issued the sessions and
// resumes them, and the audit emitter.
type Config struct {
	Backend session.Backend
	Audit   httpx.Audit
}

// Endpoints returns the session endpoints served over cfg.Backend. It returns ErrInvalidConfig or
// the error of routes.NewEndpoint.
//
// Their guarantees:
//   - GET /session answers {subject, tenant, factors, amr, remember_me, return_to,
//     password_change_required} of the resumed session, a must-change session included.
//   - POST /logout ends the presented session on the backend that issued it and clears its
//     credentials (D-02); there is no other revoker. It needs no live session, so an expired one
//     can still sign out, and it never fails for an absent or unknown credential. When the backend
//     is unavailable it answers 503 and keeps the credentials so that the client can retry.
//   - POST /logout-everywhere needs an established session but no freshness (C-71): it ends every
//     session of the caller, the presented one included, through the backend's revoke-all path
//     (the Disabled row of DESIGN §7.2), then clears the caller's credentials. When the backend
//     is unavailable it answers 503 before ending anything, keeping the caller's credentials.
//   - POST /refresh is for Bearer clients: it resumes the Bearer credentials, renewing them when
//     due, and answers the /session body with the new credentials in the response headers. A
//     request carrying any cookie, or a session of another transport or tenant, is refused (401).
func Endpoints(cfg Config) ([]routes.Endpoint, error) {
	if cfg.Backend == nil || cfg.Audit == nil {
		return nil, ErrInvalidConfig
	}
	h := handlers{backend: cfg.Backend, audit: cfg.Audit}
	fns := []struct {
		path string
		f    httpx.EndpointFunc
	}{
		{routes.Session, h.session},
		{routes.Logout, h.logout},
		{routes.LogoutEverywhere, h.logoutEverywhere},
		{routes.Refresh, h.refresh},
	}
	out := make([]routes.Endpoint, 0, len(fns))
	for _, e := range fns {
		ep, err := routes.NewEndpoint(e.path, e.f)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, nil
}

type handlers struct {
	backend session.Backend
	audit   httpx.Audit
}

type view struct {
	Subject                string   `json:"subject"`
	Tenant                 string   `json:"tenant"`
	Factors                []string `json:"factors"`
	AMR                    []string `json:"amr"`
	RememberMe             bool     `json:"remember_me"`
	ReturnTo               string   `json:"return_to"`
	PasswordChangeRequired bool     `json:"password_change_required"`
}

func viewOf(a core.SessionAttrs) view {
	fs := a.Factors()
	codes := make([]string, len(fs))
	for i, f := range fs {
		codes[i] = f.Code()
	}
	amr := a.AMR()
	if amr == nil {
		amr = []string{}
	}
	return view{
		Subject: a.Subject().User.String(), Tenant: a.Subject().Tenant.String(), Factors: codes, AMR: amr,
		RememberMe: a.RememberMe(), ReturnTo: a.ReturnTo(), PasswordChangeRequired: a.MustChangePassword(),
	}
}

func failure(err error) error {
	if errors.Is(err, httpx.ErrUnavailable) {
		return errors.Join(httpx.ErrServiceUnavailable, err)
	}
	return errors.Join(httpx.ErrUnauthenticated, err)
}

func (h handlers) emit(ctx context.Context, s audit.Scope, reason string) {
	_ = h.audit.Emit(ctx, event.Logout, s, audit.Detail{Reason: reason}, nil)
}

func (h handlers) session(w http.ResponseWriter, r *httpx.Request) {
	res, ok := r.Session()
	if !ok {
		r.Fail(w, httpx.ErrUnauthenticated)
		return
	}
	r.Respond(w, httpx.Response{Body: viewOf(res.Attrs())})
}

func (h handlers) logout(w http.ResponseWriter, r *httpx.Request) {
	if err := h.backend.End(r.Context(), w, r.HTTP()); err != nil {
		cookie.Discard(w)
		r.Fail(w, failure(err))
		return
	}
	h.emit(r.Context(), audit.Scope{TenantID: r.Tenant().String()}, "logout")
	r.Respond(w, httpx.Response{})
}

func (h handlers) logoutEverywhere(w http.ResponseWriter, r *httpx.Request) {
	res, ok := r.Session()
	if !ok {
		r.Fail(w, httpx.ErrUnauthenticated)
		return
	}
	s := res.Attrs().Subject()
	if err := h.backend.OnDisabled(r.Context(), lifecycle.AccountEvent{Subject: s}); err != nil {
		r.Fail(w, failure(err))
		return
	}
	cookie.Discard(w)
	if err := h.backend.End(r.Context(), w, r.HTTP()); err != nil {
		r.Fail(w, failure(err))
		return
	}
	h.emit(r.Context(), audit.Scope{TenantID: s.Tenant.String(), UserID: s.User.String()}, "logout_everywhere")
	r.Respond(w, httpx.Response{})
}

func (h handlers) refresh(w http.ResponseWriter, r *httpx.Request) {
	if cookie.Present(r.HTTP()) {
		r.Fail(w, errors.Join(httpx.ErrUnauthenticated, errors.New("endpoints: /refresh is for Bearer clients")))
		return
	}
	held := &heldHeaders{h: http.Header{}}
	res, err := h.backend.Resume(r.Context(), held, r.HTTP(), r.Tenant())
	if err != nil {
		r.Fail(w, failure(err))
		return
	}
	a := res.Attrs()
	if a.Transport() != core.TransportBearer || a.Subject().Tenant != r.Tenant() {
		r.Fail(w, errors.Join(httpx.ErrUnauthenticated, errors.New("endpoints: session of another transport or tenant")))
		return
	}
	for k, vs := range held.h {
		w.Header()[k] = vs
	}
	r.Respond(w, httpx.Response{Body: viewOf(a)})
}

type heldHeaders struct {
	h http.Header
}

func (w *heldHeaders) Header() http.Header { return w.h }

func (w *heldHeaders) Write(b []byte) (int, error) { return len(b), nil }

func (w *heldHeaders) WriteHeader(int) {}
