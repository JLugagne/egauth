package identity_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/identity"
	identitymem "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokenmem "github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
)

// The examples below wire the recommended login + refresh stack with the in-memory backends
// (swap in the pgx stores for production). They are runnable, so `go test` compiles and exercises
// them and `go doc` renders them.

// Example shows the minimal recommended stack: an identity.Service for the credential flows and a
// jwt issuer for the tokens. It registers a user, authenticates them, issues an access+refresh
// pair, then rotates (refreshes) that pair. Errors are handled with log.Fatal for brevity; a real
// application maps them to HTTP responses (see the identity.LoginHandler / tokens.RefreshHandler
// example).
func Example() {
	ctx := context.Background()
	const tenant = "" // empty string is the single-tenant default partition

	// --- identity: credential verification + account lifecycle ---
	idStore := identitymem.NewStore()
	svc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy())

	// --- tokens: stateless access tokens + stateful refresh-token rotation ---
	// claimsProvider re-derives a user's claims on every refresh, so a disabled or
	// role-changed user is re-evaluated rather than frozen at login.
	claimsProvider := tokens.ClaimsProviderFunc[struct{}](
		func(_ context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
		},
	)
	issuer := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:          tokenmem.NewStore[struct{}](),
		Issuer:         "example-app",
		SecretKey:      "a-32-byte-minimum-hs256-signing-secret!!",
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     720 * time.Hour,
		ClaimsProvider: claimsProvider, // required for Rotate (refresh)
	})

	// Register and authenticate.
	user, err := svc.Register(ctx, tenant, "alice@example.com", "Correct-Horse-Battery-Staple-9")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, tenant, "password", "alice@example.com", "Correct-Horse-Battery-Staple-9"); err != nil {
		log.Fatal(err)
	}

	// Issue the initial token pair for the authenticated user.
	pair, err := issuer.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: user.ID, TenantID: tenant})
	if err != nil {
		log.Fatal(err)
	}

	// Later: refresh. Rotation issues a brand-new pair and single-use-consumes the old refresh
	// token (replaying it trips theft detection and revokes the family).
	refreshed, err := issuer.Rotate(ctx, tenant, pair.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}

	// The rotated access token verifies and carries the same subject.
	claims, err := issuer.VerifyAccessToken(ctx, refreshed.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(claims.Subject == user.ID)
	// Output: true
}

// ExampleNewSingleTenant shows the single-tenant convenience facade: in an app with exactly one
// tenant, wrap the Service once and call its methods without threading the tenant argument.
func ExampleNewSingleTenant() {
	ctx := context.Background()
	svc := identity.NewService(identitymem.NewStore(), argon2.NewHasher(), policy.NewDefaultPolicy())

	app := identity.NewSingleTenant(svc) // every call uses the empty tenant ("")

	user, err := app.Register(ctx, "bob@example.com", "Correct-Horse-Battery-Staple-9")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(user.Email)
	// Output: bob@example.com
}

// ExampleLoginHandler wires the à-la-carte HTTP handlers on a standard net/http mux: login (mints
// the token pair), refresh (rotates it), logout (revokes the family) and a RequireAuth-protected
// route. egauth imposes no router — you mount the http.HandlerFunc factories yourself. This mirrors
// the README quickstart and exists so the compiler verifies those signatures.
func ExampleLoginHandler() {
	svc := identity.NewService(identitymem.NewStore(), argon2.NewHasher(), policy.NewDefaultPolicy())

	tokenStore := tokenmem.NewStore[struct{}]()
	issuer := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokenStore,
		Issuer:     "example-app",
		SecretKey:  "a-32-byte-minimum-hs256-signing-secret!!",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 720 * time.Hour,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](
			func(_ context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[struct{}], error) {
				return tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID}, nil
			},
		),
	})

	claimsOf := func(u *identity.User) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: u.ID, TenantID: u.TenantID}
	}

	mux := http.NewServeMux()
	mux.Handle("POST /login", identity.LoginHandler(svc, issuer, claimsOf))
	mux.Handle("POST /refresh", tokens.RefreshHandler[struct{}](issuer))
	mux.Handle("POST /logout", tokens.LogoutHandler(tokenStore))
	mux.Handle("GET /me", tokens.RequireAuth[struct{}](issuer,
		func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, _ struct{}) {
			_ = actor.UserID // authenticated
		}))

	fmt.Println(mux != nil)
	// Output: true
}
