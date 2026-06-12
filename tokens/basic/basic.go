// Package basic is a non-generic convenience layer over the generic tokens API for the
// common case of an application that needs NO custom JWT claims.
//
// The core tokens packages are generic in a custom-claims type C (tokens.Claims[C],
// jwt.Config[C], tokens.RequireAuth[C], ...). An application that carries no application
// data in its tokens would otherwise have to spell the empty type argument [struct{}] at
// roughly a dozen call sites. This package specializes the documented login + refresh +
// protect path to C = struct{}, so the quickstart wires up with ZERO type arguments in user
// code.
//
// It is a THIN facade: every symbol is a type alias or a one-line wrapper over the existing
// generic API — no behavior is reimplemented and nothing in tokens, tokens/jwt or
// tokens/memory is changed. If you DO need custom claims, use the generic API directly with
// your own C; this package is purely additive sugar for the no-claims case.
package basic

import (
	"context"
	"net/http"

	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
)

// Claims is tokens.Claims specialized to no custom claims. Use it everywhere the generic
// API asks for tokens.Claims[struct{}].
type Claims = tokens.Claims[struct{}]

// TokenPair is tokens.TokenPair specialized to no custom claims.
type TokenPair = tokens.TokenPair[struct{}]

// Store is tokens.Store specialized to no custom claims — the persistence seam for refresh
// tokens and API keys.
type Store = tokens.Store[struct{}]

// Issuer is the concrete JWT service specialized to no custom claims. It implements the
// tokens.Issuer, tokens.Verifier and tokens.Rotator behavior used by the quickstart.
type Issuer = jwt.Service[struct{}]

// Config configures NewIssuer. It is jwt.Config specialized to no custom claims; every field
// behaves exactly as documented on jwt.Config.
type Config = jwt.Config[struct{}]

// NewMemoryStore returns an in-memory tokens.Store for the no-claims case (wrapping
// memory.NewStore[struct{}]). Use tokens/pgx for production persistence.
func NewMemoryStore() Store {
	return memory.NewStore[struct{}]()
}

// NewIssuer builds a JWT issuer for the no-claims case (wrapping jwt.New[struct{}]). Like
// jwt.New it panics on a configuration from which no coherent signer can be built; call
// cfg.Validate for comprehensive startup checks.
func NewIssuer(cfg Config) *Issuer {
	return jwt.New[struct{}](cfg)
}

// ClaimsProviderFunc adapts a plain function to the claims-provider seam the JWT Config needs
// for refresh rotation (tokens.ClaimsProviderFunc[struct{}]). Assign the result to
// Config.ClaimsProvider.
type ClaimsProviderFunc = tokens.ClaimsProviderFunc[struct{}]

// AuthenticatedHandlerFunc is the next-handler signature for RequireAuth, specialized to no
// custom claims (tokens.AuthenticatedHandlerFunc[struct{}]).
type AuthenticatedHandlerFunc = tokens.AuthenticatedHandlerFunc[struct{}]

// RefreshHandler builds the refresh-rotation HTTP handler for the no-claims case (wrapping
// tokens.RefreshHandler[struct{}]). Pass the Issuer (it is the Rotator) plus any
// tokens.HandlerOption.
func RefreshHandler(rotator tokens.Rotator[struct{}], opts ...tokens.HandlerOption) http.HandlerFunc {
	return tokens.RefreshHandler[struct{}](rotator, opts...)
}

// LogoutHandler builds the family-revoking logout HTTP handler. It is identical to
// tokens.LogoutHandler (which is already non-generic) and is re-exported here so the whole
// quickstart surface lives in one package.
func LogoutHandler(revoker tokens.FamilyRevoker, opts ...tokens.HandlerOption) http.HandlerFunc {
	return tokens.LogoutHandler(revoker, opts...)
}

// RequireAuth builds the access-token-verifying middleware for the no-claims case (wrapping
// tokens.RequireAuth[struct{}]). The next handler receives the authenticated egauth.Actor;
// the custom-claims argument is the empty struct{}.
func RequireAuth(verifier tokens.Verifier[struct{}], next AuthenticatedHandlerFunc, opts ...tokens.AuthOption[struct{}]) http.HandlerFunc {
	return tokens.RequireAuth[struct{}](verifier, next, opts...)
}

// Ensure the Issuer alias stays assignable to the generic seams it specializes.
var (
	_ tokens.Issuer[struct{}]   = (*Issuer)(nil)
	_ tokens.Verifier[struct{}] = (*Issuer)(nil)
	_ tokens.Rotator[struct{}]  = (*Issuer)(nil)
)

// ContextMiddleware builds the context bridge for the no-claims case (wrapping
// tokens.ContextMiddleware[struct{}]). It verifies the access token and injects the
// egauth.Actor into the request context before calling next, for bridging token auth into
// the passkey/mfa/otp handlers. Read the Actor back with tokens.ActorFromContext.
func ContextMiddleware(verifier tokens.Verifier[struct{}], next http.Handler, opts ...tokens.AuthOption[struct{}]) http.Handler {
	return tokens.ContextMiddleware[struct{}](verifier, next, opts...)
}

// ClaimsFromContext returns the verified no-claims Claims injected by ContextMiddleware.
// It is tokens.ClaimsFromContext specialized to struct{}; the custom-claims field is empty.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	return tokens.ClaimsFromContext[struct{}](ctx)
}
