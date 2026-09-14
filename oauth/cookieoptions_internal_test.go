package oauth

import (
	"testing"

	"github.com/JLugagne/egauth/tokens"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCookieOptionsStaySelfConsistent pins that the OAuth cookie options leave the handler
// configuration valid on its own, so a callback can never panic while writing its cookies.
func TestCookieOptionsStaySelfConsistent(t *testing.T) {
	cases := map[string][]HandlerOption{
		"defaults":        nil,
		"domain":          {WithCookieDomain("example.com")},
		"insecure":        {WithInsecureCookies()},
		"domain+insecure": {WithCookieDomain("example.com"), WithInsecureCookies()},
		"insecure+domain": {WithInsecureCookies(), WithCookieDomain("example.com")},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := newHandlerConfig(opts)
			require.NoError(t, cfg.cookies.Validate())
		})
	}
}

// TestWithCookiesRejectsInvalidValueAtConstruction pins that an invalid hand-built value is refused
// when the handler is built, not on the first request.
func TestWithCookiesRejectsInvalidValueAtConstruction(t *testing.T) {
	bad := tokens.DefaultCookies()
	bad.Domain = "example.com"
	assert.Panics(t, func() { newHandlerConfig([]HandlerOption{WithCookies(bad)}) })
}
