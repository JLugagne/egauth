package basic_test

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
	"github.com/JLugagne/egauth/tokens/basic"
	"github.com/google/uuid"
)

// Example wires the recommended login + refresh + protect stack for an application that needs
// NO custom JWT claims, using the basic convenience layer. Note there is not a single
// [struct{}] type argument anywhere in this user code — that is the whole point of the
// package. An application that DOES carry custom claims uses the generic tokens API directly.
func Example() {
	ctx := context.Background()
	const tenant = "" // empty string is the single-tenant default partition

	// --- identity: credential verification + account lifecycle ---
	idStore := identitymem.NewStore()
	svc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy())

	// --- tokens: stateless access tokens + refresh-token rotation, no custom claims ---
	// claimsProvider re-derives a user's claims on every refresh, so a disabled or
	// role-changed user is re-evaluated rather than frozen at login.
	claimsProvider := basic.ClaimsProviderFunc(
		func(_ context.Context, userID uuid.UUID, tenantID string) (basic.Claims, error) {
			return basic.Claims{Subject: userID, TenantID: tenantID}, nil
		},
	)
	tokenStore := basic.NewMemoryStore() // or tokens/pgx.NewStore(pool)
	issuer := basic.NewIssuer(basic.Config{
		Store:          tokenStore,
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

	// Issue the initial token pair for the authenticated user.
	pair, err := issuer.IssueTokenPair(ctx, basic.Claims{Subject: user.ID, TenantID: tenant})
	if err != nil {
		log.Fatal(err)
	}

	// Later: refresh. Rotation issues a brand-new pair and single-use-consumes the old token.
	refreshed, err := issuer.Rotate(ctx, tenant, pair.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}

	// Protect a route with the access-token middleware. The next handler receives the
	// authenticated actor; the custom-claims argument is the empty struct{}.
	mux := http.NewServeMux()
	mux.Handle("POST /refresh", basic.RefreshHandler(issuer)) // issuer is the Rotator
	mux.Handle("POST /logout", basic.LogoutHandler(tokenStore))
	mux.Handle("GET /me", basic.RequireAuth(issuer,
		func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, _ struct{}) {
			_ = actor.UserID // authenticated
		}))

	// The rotated access token verifies and carries the same subject.
	claims, err := issuer.VerifyAccessTokenForTenant(ctx, "", refreshed.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(claims.Subject == user.ID)
	// Output: true
}
