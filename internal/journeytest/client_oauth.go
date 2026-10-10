package journeytest

import (
	"context"
	"net/http"
	"net/url"

	"github.com/JLugagne/egauth"
)

// BeginOAuth starts the browser ceremony of the World's provider and returns the begin response, whose
// AuthorizationURL is where the provider asks the user to sign in; under cookies its bind cookie
// lands in the jar.
func (c *Client) BeginOAuth() *Resp {
	c.T.Helper()
	return c.Do(Req{Path: "/auth" + concrete(egauth.PathOAuthBegin)})
}

// AuthorizationURL returns the provider URL a begin response sends the browser to: its Location
// under cookies, the authorization_url member of the body under the Bearer transport.
func AuthorizationURL(begin *Resp) string {
	if loc := begin.Header.Get("Location"); loc != "" {
		return loc
	}
	return begin.Field("authorization_url")
}

// OAuthState returns the state the authorization URL of a begin response carries, or "".
func OAuthState(begin *Resp) string {
	loc, err := url.Parse(AuthorizationURL(begin))
	if err != nil {
		return ""
	}
	return loc.Query().Get("state")
}

// AuthorizeAtIdP follows the begin response to the World's fake provider, which signs the user in
// at once, and returns the callback path and query it redirects to.
func (w *World) AuthorizeAtIdP(begin *Resp) string {
	w.T.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, AuthorizationURL(begin), nil)
	if err != nil {
		w.T.Fatalf("journeytest: authorization URL: %v", err)
	}
	res, err := w.IdP.HTTPClient().Do(req)
	if err != nil {
		w.T.Fatalf("journeytest: authorizing at the provider: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	back, err := url.Parse(res.Header.Get("Location"))
	if err != nil || back.Path == "" {
		w.T.Fatalf("journeytest: the provider answered %d without a redirect", res.StatusCode)
	}
	return back.RequestURI()
}

// CompleteOAuth runs the whole browser ceremony of the World's provider on c and returns the
// callback response. It needs Settings.LoopbackIdP, or the callback ends in 502.
func (c *Client) CompleteOAuth(w *World) *Resp {
	c.T.Helper()
	begin := c.BeginOAuth()
	return c.Do(Req{Path: w.AuthorizeAtIdP(begin)})
}
