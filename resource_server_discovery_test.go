package egauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/egauthtest"
	"github.com/JLugagne/egauth/memstore"
)

type stubAuth struct {
	srv  *httptest.Server
	doc  map[string]any
	jwks string
	hook func(w http.ResponseWriter, r *http.Request) bool
}

func newStubAuth(t *testing.T) *stubAuth {
	t.Helper()
	s := &stubAuth{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.hook != nil && s.hook(w, r) {
			return
		}
		switch r.URL.Path {
		case egauth.PathWellKnown:
			_ = json.NewEncoder(w).Encode(s.doc)
		case "/auth" + egauth.PathJWKS:
			_, _ = w.Write([]byte(s.jwks))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.srv.Close)
	s.doc = map[string]any{
		"issuer": s.srv.URL, "jwks_uri": s.srv.URL + "/auth" + egauth.PathJWKS, "audiences": []string{rsAudience},
		"claims_fingerprint": egauth.ClaimsFingerprint[gateClaims](),
	}
	jwks, err := edSigner(t, "stub-1").Verifier().PublicJWK()
	require.NoError(t, err)
	s.jwks = `{"keys":[` + string(jwks) + `]}`
	return s
}

func (s *stubAuth) config(t *testing.T) egauth.ResourceConfig {
	return egauth.ResourceConfig{
		AuthOrigin: s.srv.URL, Audience: rsAudience, Proxy: egauth.DirectClients(),
		Revocation: egauth.FromStorage(memstore.New(testKEK(t))),
	}
}

func (s *stubAuth) build(t *testing.T) error {
	t.Helper()
	rs, err := egauth.NewLoopbackResourceServer[gateClaims](s.config(t), egauthtest.NewClock(time.Time{}).Library())
	if err == nil {
		require.NoError(t, rs.Close())
	}
	return err
}

func TestResourceServerDiscoveryStubAcceptsAWellFormedDocument(t *testing.T) {
	require.NoError(t, newStubAuth(t).build(t))
}

func TestResourceServerDiscoveryMismatchesAreConfigErrors(t *testing.T) {
	cases := map[string]struct {
		mut     func(*stubAuth)
		field   string
		problem string
	}{
		"issuer is another origin":    {func(s *stubAuth) { s.doc["issuer"] = "https://evil.example.com" }, "AuthOrigin", "discovery issuer"},
		"issuer has a trailing slash": {func(s *stubAuth) { s.doc["issuer"] = s.srv.URL + "/" }, "AuthOrigin", "discovery issuer"},
		"audience missing":            {func(s *stubAuth) { s.doc["audiences"] = []string{} }, "Audience", "not one of the audiences"},
		"fingerprint differs":         {func(s *stubAuth) { s.doc["claims_fingerprint"] = "other" }, "AuthOrigin", "claims type"},
		"no jwks":                     {func(s *stubAuth) { delete(s.doc, "jwks_uri") }, "AuthOrigin", "no JWKS"},
		"jwks on another origin": {func(s *stubAuth) {
			s.doc["jwks_uri"] = "https://evil.example.com/auth/jwks.json"
		}, "AuthOrigin", "not on AuthOrigin"},
		"jwks on a sibling prefix": {func(s *stubAuth) { s.doc["jwks_uri"] = s.srv.URL + ".evil.example.com/jwks" }, "AuthOrigin", "not on AuthOrigin"},
		"jwks holds a symmetric key": {func(s *stubAuth) {
			s.jwks = `{"keys":[{"kty":"oct","kid":"hs","alg":"HS256","k":"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"}]}`
		}, "AuthOrigin", "JWKS unavailable"},
		"jwks is empty": {func(s *stubAuth) { s.jwks = `{"keys":[]}` }, "AuthOrigin", "JWKS unavailable"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := newStubAuth(t)
			c.mut(s)
			err := s.build(t)
			requireField(t, err, c.field)
			require.Contains(t, err.Error(), c.problem)
		})
	}
}

func TestResourceServerDiscoveryFetchFailuresAreConfigErrors(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, r *http.Request) bool{
		"server error": func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == egauth.PathWellKnown {
				w.WriteHeader(http.StatusInternalServerError)
				return true
			}
			return false
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == egauth.PathWellKnown {
				http.Redirect(w, r, "https://evil.example.com/", http.StatusFound)
				return true
			}
			return false
		},
		"not json": func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == egauth.PathWellKnown {
				_, _ = w.Write([]byte("<html>"))
				return true
			}
			return false
		},
		"oversized document": func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == egauth.PathWellKnown {
				_, _ = w.Write([]byte(`{"issuer":"` + strings.Repeat("a", 70<<10) + `"}`))
				return true
			}
			return false
		},
		"jwks server error": func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/auth"+egauth.PathJWKS {
				w.WriteHeader(http.StatusBadGateway)
				return true
			}
			return false
		},
		"oversized jwks": func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/auth"+egauth.PathJWKS {
				_, _ = w.Write([]byte(strings.Repeat(" ", 300<<10)))
				return true
			}
			return false
		},
	}
	for name, hook := range cases {
		t.Run(name, func(t *testing.T) {
			s := newStubAuth(t)
			s.hook = hook
			requireField(t, s.build(t), "AuthOrigin")
		})
	}
}
