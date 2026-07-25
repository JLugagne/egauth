package webapp_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/JLugagne/egauth/identity"
	identitymem "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/basic"
	"github.com/JLugagne/egauth/webapp"
)

// ExampleNewWebApp shows the batteries-included preset: a few lines wire identity + tokens
// into a single mounted http.Handler with secure-by-default cookies, CSRF and a non-nil
// event sink. The à-la-carte handlers stay available for anything the preset does not cover.
//
// The preset also makes account deactivation end access: it registers the tokens account revoker
// on the identity service and re-checks account status on every refresh rotation, so
// idSvc.DisableUser both revokes the user's refresh families and refuses any further /auth/refresh.
func ExampleNewWebApp() {
	// Compose the dependencies from the public, in-memory backends.
	idStore := identitymem.NewStore()
	idSvc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy())

	handler, err := webapp.NewWebApp(webapp.Config{
		Identity:   idSvc,
		TokenStore: basic.NewMemoryStore(),
		SigningKey: "a-high-entropy-secret-kept-out-of-source-control",
		Issuer:     "example-app",
		// A real deployment lists the origins its forms are served from, e.g.
		// TrustedOrigins: []string{"app.example.com"}, which enforces a strict same-origin CSRF
		// check on every mounted endpoint. This runnable example drives the handler with
		// http.PostForm (which sends no Origin header), so it opts out instead.
		InsecureNoOriginCheck: true,
		// EventSink left nil -> events go to slog.Default() instead of being dropped.
	})
	if err != nil {
		log.Fatal(err)
	}

	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Register a new account; on success the preset auto-logs the user in by setting the
	// access + refresh cookies.
	form := url.Values{"email": {"alice@example.com"}, "password": {"Correct horse battery staple 1!"}}
	resp, err := http.PostForm(srv.URL+"/auth/register", form)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var gotAccessCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == tokens.DefaultAccessCookieName {
			gotAccessCookie = true
		}
	}

	fmt.Println("status:", resp.StatusCode)
	fmt.Println("access cookie set:", gotAccessCookie)
	// Output:
	// status: 204
	// access cookie set: true
}
