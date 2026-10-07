package egauth_test

import (
	"testing"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/routes"
)

func TestRootConstantsMirrorRoutes(t *testing.T) {
	if egauth.HeaderTransport != "X-Egauth-Transport" || routes.HeaderTransport != egauth.HeaderTransport {
		t.Fatal("transport header mismatch")
	}
	if egauth.PathLogin != routes.Login || egauth.PathOAuthCallback != routes.OAuthCallback ||
		egauth.FieldReturnTo != routes.FieldReturnTo || egauth.PathWellKnown != "/.well-known/egauth-configuration" {
		t.Fatal("root constants must mirror internal/routes")
	}
}
