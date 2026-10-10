package egauth

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/session/jwt"
)

type resourceTokenBody struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresAt string `json:"expires_at"`
}

type resourceTokens struct {
	backend   *jwt.Backend
	audiences []string
	lifetime  time.Duration
}

func resourceTokenEndpoint(be *jwt.Backend, audiences []string, lifetime time.Duration) (routes.Endpoint, error) {
	rt := resourceTokens{backend: be, audiences: slices.Clone(audiences), lifetime: lifetime}
	return routes.NewEndpoint(routes.ResourceToken, rt.mint)
}

func (rt resourceTokens) mint(w http.ResponseWriter, r *httpx.Request) {
	res, ok := r.Session()
	if !ok {
		r.Fail(w, httpx.ErrUnauthenticated)
		return
	}
	audience := r.Field(routes.FieldResource)
	if audience == "" || !slices.Contains(rt.audiences, audience) {
		r.Fail(w, httpx.ErrInvalidRequest)
		return
	}
	raw, expires, err := rt.backend.MintResource(r.Context(), res, audience, rt.lifetime)
	switch {
	case errors.Is(err, jwt.ErrAudience):
		r.Fail(w, errors.Join(httpx.ErrInvalidRequest, err))
		return
	case errors.Is(err, httpx.ErrUnavailable):
		r.Fail(w, errors.Join(httpx.ErrServiceUnavailable, err))
		return
	case err != nil:
		r.Fail(w, errors.Join(httpx.ErrUnauthenticated, err))
		return
	}
	r.Respond(w, httpx.Response{Body: resourceTokenBody{Token: raw, TokenType: "Bearer", ExpiresAt: expires.UTC().Format(time.RFC3339)}})
}
