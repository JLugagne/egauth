package identity

import (
	"testing"

	"github.com/JLugagne/egauth/tokens"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func defaultCookiesWithDomain() tokens.Cookies {
	c := tokens.DefaultCookies()
	c.Domain = "example.com"
	return c
}

// TestCookieOptionsStaySelfConsistent pins that every cookie-shaping option leaves the handler
// configuration valid on its own, so no handler can ever be built with a configuration a browser
// would reject.
func TestCookieOptionsStaySelfConsistent(t *testing.T) {
	cases := map[string][]HandlerOption{
		"defaults":        nil,
		"domain":          {WithCookieDomain("example.com")},
		"path":            {WithCookiePath("/app")},
		"refresh path":    {WithRefreshCookiePath("/auth/refresh")},
		"insecure":        {WithInsecureCookies()},
		"domain+path":     {WithCookieDomain("example.com"), WithCookiePath("/app")},
		"insecure+domain": {WithInsecureCookies(), WithCookieDomain("example.com")},
		"domain+insecure": {WithCookieDomain("example.com"), WithInsecureCookies()},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := newHandlerConfig(opts)
			require.NoError(t, cfg.cookies.Validate())
		})
	}
}

// TestWithCookiesRejectsInvalidValueAtConstruction pins that a hand-built value keeping the __Host-
// prefix alongside a Domain is refused when the handler is built, not on the first request.
func TestWithCookiesRejectsInvalidValueAtConstruction(t *testing.T) {
	bad := defaultCookiesWithDomain()
	assert.Panics(t, func() { newHandlerConfig([]HandlerOption{WithCookies(bad)}) })
}
