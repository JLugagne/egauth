package egauth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/signing"
)

type discoveryDocument struct {
	Issuer            string   `json:"issuer"`
	JWKSURI           string   `json:"jwks_uri,omitempty"`
	Audiences         []string `json:"audiences"`
	ClaimsFingerprint string   `json:"claims_fingerprint"`
}

func (a *Auth[C]) publishesJWKS() bool {
	spec, k := backendOf(a.cfg.Sessions)
	if spec.kind != backendJWT || a.owned.keys == nil {
		return false
	}
	return k.kind == keysTenant || (k.kind == keysStatic && !k.active.IsZero() && !k.active.Verifier().Symmetric())
}

func (a *Auth[C]) discoveryEndpoints() ([]routes.Endpoint, error) {
	var out []routes.Endpoint
	if a.publishesJWKS() {
		ep, err := routes.NewEndpoint(routes.JWKS, a.jwks)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	if len(a.cfg.Audiences) > 0 {
		be, ok := a.owned.backend.(*jwt.Backend)
		if !ok {
			return nil, errors.Join(routes.ErrInvalidEndpoint, errors.New("resource tokens need the JWT session backend"))
		}
		ep, err := resourceTokenEndpoint(be, a.cfg.Audiences, a.cfg.Policy.RecheckEvery)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, nil
}

func (a *Auth[C]) jwks(w http.ResponseWriter, r *httpx.Request) {
	vs, err := a.owned.keys.Published(r.Context(), r.Tenant())
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrServiceUnavailable, err))
		return
	}
	doc, err := signing.EncodeJWKS(vs)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	r.Respond(w, httpx.Response{Body: json.RawMessage(doc)})
}

func (a *Auth[C]) discovery() (http.Handler, error) {
	meta, ok := routes.MetaFor(routes.JWKS)
	if !ok {
		return nil, errors.Join(routes.ErrInvalidEndpoint, errors.New("no registry metadata for the discovery document"))
	}
	return a.owned.preamble.Wrap(routes.WellKnown, meta, a.discoveryDocument)
}

func (a *Auth[C]) discoveryDocument(w http.ResponseWriter, r *httpx.Request) {
	o := a.owned
	issuer, err := o.origins.expand(r.Tenant())
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrUnauthenticated, err))
		return
	}
	doc := discoveryDocument{Issuer: issuer, Audiences: nonNil(a.cfg.Audiences), ClaimsFingerprint: o.fingerprint}
	if a.publishesJWKS() {
		doc.JWKSURI = issuer + a.cfg.BasePath + routes.JWKS
	}
	r.Respond(w, httpx.Response{Body: doc})
}
