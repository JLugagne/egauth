package tokens

import (
	"context"
	"net/http"

	"github.com/JLugagne/egauth"
	"github.com/google/uuid"
)

// This file is the OPT-IN context bridge. egauth's recommended surface passes the
// authenticated Actor and claims as explicit handler ARGUMENTS (see RequireAuth and
// AuthenticatedHandlerFunc) precisely so business identity is never hidden in a context.
//
// However the passkey, mfa and otp handlers each take a resolver that reads the subject
// from the request — "whatever the application's auth middleware stored on the request".
// Without an official producer for that channel, every consumer combining tokens with one
// of those modules hand-rolls the same RequireAuth -> r.Context() -> resolver adapter.
// ContextMiddleware is that producer, and the *FromContext helpers are the matching
// consumers, so the cross-module wiring becomes a one-liner.
//
// Reach for this ONLY to bridge into those resolver-based modules. For your own handlers,
// prefer RequireAuth's explicit arguments.

// ctxKey is an unexported, zero-size context key. Unexported means no code outside this
// package can forge an authenticated entry or collide with the slot.
type ctxKey struct{}

// authContext is what ContextMiddleware stores: the Actor and the full verified Claims[C]
// together, so ClaimsFromContext needs no second lookup and the two can never disagree.
type authContext[C any] struct {
	actorValue egauth.Actor
	claims     *Claims[C]
}

// actorCarrier exposes the Actor without naming C, so ActorFromContext can stay
// non-generic — the resolver-based modules that consume it do not know the claims type.
type actorCarrier interface {
	actor() egauth.Actor
}

func (a authContext[C]) actor() egauth.Actor { return a.actorValue }

// assuranceCarrier exposes the assurance summary without naming C, so AssuranceFromContext can
// stay non-generic — the identity and mfa handlers enforce it without knowing the claims type.
type assuranceCarrier interface {
	assurance() Assurance
}

func (a authContext[C]) assurance() Assurance {
	if a.claims == nil {
		return Assurance{}
	}
	return Assurance{StepUp: a.claims.SatisfiesStepUp(), Interim: a.claims.Interim}
}

// Assurance is the assurance-relevant summary of the credential that authenticated a request. The
// identity and mfa handlers consume it to enforce step-up on their factor-mutating and destructive
// routes without importing the claims type.
type Assurance struct {
	// StepUp reports whether the credential proves a completed second factor
	// (Claims.SatisfiesStepUp): its AMR records AMRMFA, AMROTP or AMRWebAuthn and it is not
	// interim.
	StepUp bool
	// Interim reports whether the credential is a PRE-STEP-UP interim one (Claims.Interim): the
	// first factor passed but the required second factor has not been completed.
	Interim bool
}

// AssuranceResolver reports the Assurance of the credential that authenticated the request. ok is
// false when the assurance cannot be determined, and every consumer MUST fail closed on it — an
// undeterminable assurance is never treated as a satisfied one. AssuranceResolverFromContext is
// the first-party implementation for handlers mounted behind ContextMiddleware.
type AssuranceResolver func(r *http.Request) (Assurance, bool)

// AssuranceFromContext returns the Assurance of the credential injected by ContextMiddleware. ok is
// false on any request that did not pass an authenticated ContextMiddleware, so callers MUST check
// it and fail closed. It is non-generic so the resolver-based modules can call it without knowing
// the claims type.
func AssuranceFromContext(ctx context.Context) (Assurance, bool) {
	carrier, ok := ctx.Value(ctxKey{}).(assuranceCarrier)
	if !ok {
		return Assurance{}, false
	}
	return carrier.assurance(), true
}

// AssuranceResolverFromContext adapts AssuranceFromContext to the AssuranceResolver shape used by
// identity.WithAssuranceResolver and mfa.WithAssuranceResolver. It is their DEFAULT, so mounting a
// factor-mutating or destructive handler behind ContextMiddleware is all the wiring their step-up
// enforcement needs:
//
//	mux.Handle("/mfa/disable", tokens.ContextMiddleware(verifier,
//	    mfa.DisableHandler(svc, mfa.WithUserResolver(tokens.UserResolverFromContext))))
func AssuranceResolverFromContext(r *http.Request) (Assurance, bool) {
	return AssuranceFromContext(r.Context())
}

// ContextMiddleware verifies the access token using the SAME fail-closed path as
// RequireAuth (header/cookie source, tenant resolver, auto-refresh, AMR and max-auth-age
// options all apply) and, on success, injects the egauth.Actor and Claims[C] into the
// request context before calling next. On any auth failure it writes the same response as
// RequireAuth (401, or 401-with-step-up) and does NOT call next.
//
// Use it only to bridge token auth into modules whose handlers read the subject from the
// request context (passkey, mfa, otp). For your own handlers prefer RequireAuth, which
// passes the Actor and claims as explicit arguments rather than through the context.
func ContextMiddleware[C any](verifier Verifier[C], next http.Handler, opts ...AuthOption[C]) http.Handler {
	cfg := authConfig[C]{readHeader: true}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.cookies != nil {
		cfg.cookies.MustValidate()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveAuthenticated(w, r, verifier, &cfg, func(w http.ResponseWriter, r *http.Request, claims *Claims[C]) {
			ctx := context.WithValue(r.Context(), ctxKey{}, authContext[C]{
				actorValue: actorFromClaims(claims),
				claims:     claims,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
}

// ActorFromContext returns the egauth.Actor injected by ContextMiddleware. ok is false on
// any request that did not pass an authenticated ContextMiddleware, so callers MUST check
// it and fail closed — a zero Actor is never an authenticated one. It is non-generic so
// the resolver-based modules can call it without knowing the claims type.
func ActorFromContext(ctx context.Context) (egauth.Actor, bool) {
	carrier, ok := ctx.Value(ctxKey{}).(actorCarrier)
	if !ok {
		return egauth.Actor{}, false
	}
	return carrier.actor(), true
}

// ClaimsFromContext returns the verified Claims[C] injected by ContextMiddleware. The C
// must match the ContextMiddleware[C] that produced the entry; a mismatch returns ok=false
// (fail closed) rather than panicking, so a wrong-C caller rejects instead of crashing.
func ClaimsFromContext[C any](ctx context.Context) (*Claims[C], bool) {
	ac, ok := ctx.Value(ctxKey{}).(authContext[C])
	if !ok {
		return nil, false
	}
	return ac.claims, true
}

// UserResolverFromContext adapts the context Actor to the (userID, tenant, ok) resolver
// shape used by mfa.WithUserResolver. Mount ContextMiddleware ahead of the mfa handler and
// pass this so the cross-module wiring is one line:
//
//	mux.Handle("/mfa/verify", tokens.ContextMiddleware(verifier,
//	    mfa.VerifyHandler(svc, mfa.WithUserResolver(tokens.UserResolverFromContext))))
func UserResolverFromContext(r *http.Request) (uuid.UUID, string, bool) {
	a, ok := ActorFromContext(r.Context())
	if !ok {
		return uuid.Nil, "", false
	}
	return a.UserID, a.TenantID, true
}

// SubjectResolverFromContext adapts the context Actor to the (subject, ok) shape used by
// otp.WithSubjectResolver. It is the otp counterpart of UserResolverFromContext.
//
// passkey deliberately has no prebuilt adapter: its resolver also needs the human-facing
// name/displayName stamped into a credential, which are application profile data, not part
// of Actor or Claims. Write that short closure and pull the name from your own user record:
//
//	passkey.WithUserResolver(func(r *http.Request) (uuid.UUID, string, string, string, bool) {
//	    a, ok := tokens.ActorFromContext(r.Context())
//	    if !ok { return uuid.Nil, "", "", "", false }
//	    return a.UserID, a.TenantID, "" /*name*/, "" /*displayName*/, true
//	})
func SubjectResolverFromContext(r *http.Request) (uuid.UUID, bool) {
	a, ok := ActorFromContext(r.Context())
	if !ok {
		return uuid.Nil, false
	}
	return a.UserID, true
}

// MustChangeResolverFromContext adapts the verified Claims[C] injected by ContextMiddleware to
// the bool resolver shape used by mfa.WithMustChangeResolver. It reports whether the interim
// token carried must_change_password, so the MFA step-up handler can keep the forced-change gate:
// when true the stepped-up full pair stays flagged (and carries the flag across refresh). The C must match the
// ContextMiddleware[C] that produced the entry; a mismatch (or an unauthenticated request)
// reports false. Mount ContextMiddleware ahead of the step-up handler and wire it in one line:
//
//	mux.Handle("/mfa/step-up", tokens.ContextMiddleware(verifier,
//	    mfa.StepUpHandler(svc, issuer, claimsOf,
//	        mfa.WithUserResolver(tokens.UserResolverFromContext),
//	        mfa.WithMustChangeResolver(tokens.MustChangeResolverFromContext[C]))))
//
// PriorAMRResolverFromContext adapts the verified Claims[C] injected by ContextMiddleware to the
// []string resolver shape used by mfa.WithPriorAMR. It reports the factors the credential carrying
// the step-up request already proved, so the step-up handlers can carry them forward instead of
// guessing: they assert only the factor they verified themselves plus these. The C must match the
// ContextMiddleware[C] that produced the entry; a mismatch (or an unauthenticated request) reports
// nil, which is the safe answer — nothing extra is asserted.
//
//	mux.Handle("/mfa/step-up", tokens.ContextMiddleware(verifier,
//	    mfa.StepUpHandler(svc, issuer, claimsOf,
//	        mfa.WithUserResolver(tokens.UserResolverFromContext),
//	        mfa.WithPriorAMR(tokens.PriorAMRResolverFromContext[C]))))
func PriorAMRResolverFromContext[C any](r *http.Request) []string {
	claims, ok := ClaimsFromContext[C](r.Context())
	if !ok {
		return nil
	}
	return claims.AMR
}

func MustChangeResolverFromContext[C any](r *http.Request) bool {
	claims, ok := ClaimsFromContext[C](r.Context())
	if !ok {
		return false
	}
	return claims.MustChangePassword
}
