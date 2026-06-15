// Package main is a runnable reference application that wires the full egauth stack:
// identity + tokens with custom claims + MFA (TOTP) + passkey + admin operations + audit
// events — all over HTTP using only in-memory backends and the standard library mux.
//
// This application is intentionally self-contained: it imports only the published egauth
// module (github.com/JLugagne/egauth) and builds with a plain "go build" from the module
// proxy without requiring a local go.work workspace.
//
// # Routes
//
//	POST /auth/register          Register a new account (form: email, password)
//	POST /auth/login             Authenticate and receive JWT access+refresh cookies (form: email, password)
//	POST /auth/refresh           Rotate the refresh token (cookie-driven)
//	POST /auth/logout            Revoke the current refresh-token family (cookie-driven)
//
//	POST /mfa/enroll             Begin TOTP enrollment for the authenticated user
//	POST /mfa/confirm            Confirm TOTP enrollment with a live code (form: code)
//	POST /mfa/verify             Verify a TOTP code as a step-up factor (form: code)
//
//	POST /passkey/register/begin    Begin passkey credential registration
//	POST /passkey/register/finish   Finish passkey credential registration
//	POST /passkey/login/begin       Begin passkey login ceremony
//	POST /passkey/login/finish      Finish passkey login ceremony (triggers onLoginSuccess)
//
//	POST /admin/disable/:userID   Administratively disable an account (admin-only role check)
//	POST /admin/enable/:userID    Re-enable a disabled account (admin-only role check)
//	POST /admin/mfa/unlock/:userID Unlock a locked MFA enrollment (admin-only role check)
//
//	GET  /me                     Return authenticated user ID (protected route, demo only)
//
// # Custom claims
//
// The token custom-claims type carries a Role field ("user" or "admin"), demonstrating
// the generic tokens/jwt API with C = AppClaims.
//
// # Audit
//
// All modules are wired with an event.Sink backed by slog.Default(), so every
// authentication event (login success/failure, TOTP verify, passkey verify, admin actions)
// is written to structured logs.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	identitymem "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/mfa"
	mfamem "github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/passkey"
	passkeymem "github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokenmem "github.com/JLugagne/egauth/tokens/memory"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

// AppClaims carries the application-specific data embedded in every JWT.
// Using a named type instead of struct{} demonstrates the generic tokens/jwt API.
type AppClaims struct {
	// Role is "user" or "admin". Admin routes require Role == "admin".
	Role string `json:"role,omitempty"`
}

// isAdmin guards admin-only routes: requires the caller to carry an "admin" role in their
// JWT custom claims. Returns 403 and false on failure.
func isAdmin(claims *tokens.Claims[AppClaims], w http.ResponseWriter) bool {
	if claims == nil || claims.Custom.Role != "admin" {
		http.Error(w, "forbidden: admin role required", http.StatusForbidden)
		return false
	}
	return true
}

// BuildServer wires the full egauth stack and returns the configured mux.
// Extracted from main so it can be exercised by the smoke test.
func BuildServer() (http.Handler, error) {
	ctx := context.Background()
	_ = ctx

	// ------------------------------------------------------------------ audit
	// All modules share a single slog-backed event sink so every auth event
	// (login success/failure, TOTP verify, passkey verify, admin actions) lands
	// in structured logs. Replace with your own Sink implementation for metrics,
	// alerting, or a dedicated audit store.
	audit := event.NewSlogSink(slog.Default())

	// ------------------------------------------------------------------ identity
	idStore := identitymem.NewStore()
	idSvc := identity.NewService(
		idStore,
		argon2.NewHasher(),
		policy.NewDefaultPolicy(),
		identity.WithEventSink(audit),
	)

	// ------------------------------------------------------------------ tokens (custom claims)
	// ClaimsProvider re-derives the user's role on every refresh, so a
	// role change takes effect without waiting for the access token to expire.
	tokenStore := tokenmem.NewStore[AppClaims]()
	claimsProvider := tokens.ClaimsProviderFunc[AppClaims](
		func(_ context.Context, userID uuid.UUID, tenantID string) (tokens.Claims[AppClaims], error) {
			// In production, look up the user's role from your data store.
			// Here every user is "user"; an admin would set Role: "admin".
			return tokens.Claims[AppClaims]{
				Subject:  userID,
				TenantID: tenantID,
				Custom:   AppClaims{Role: "user"},
			}, nil
		},
	)
	issuer := jwt.New[AppClaims](jwt.Config[AppClaims]{
		Store:          tokenStore,
		Issuer:         "egauth-fullstack-example",
		SecretKey:      "replace-with-a-32-byte-minimum-secret-in-production!",
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     720 * time.Hour,
		ClaimsProvider: claimsProvider,
		EventSink:      audit,
	})

	// claimsOf maps a freshly authenticated identity.User to the initial token claims.
	claimsOf := func(u *identity.User) tokens.Claims[AppClaims] {
		return tokens.Claims[AppClaims]{
			Subject:  u.ID,
			TenantID: u.TenantID,
			Custom:   AppClaims{Role: "user"},
		}
	}

	// cookies configures JWT cookies: Secure + SameSite=Lax by default.
	// WithInsecureCookies() is NOT set so the defaults are secure; for local
	// HTTP development behind a TLS terminator this works as-is.
	cookies := tokens.DefaultCookies()

	// ------------------------------------------------------------------ MFA (TOTP)
	mfaStore := mfamem.NewStore()
	mfaSvc := mfa.NewService(
		mfaStore,
		mfa.WithIssuer("egauth-fullstack-example"),
		mfa.WithEventSink(audit),
	)

	// ------------------------------------------------------------------ passkey
	passkeyStore := passkeymem.NewStore()
	challengeStore := passkeymem.NewChallengeStore()
	cookieKey := make([]byte, 32) // zero key — replace with crypto/rand in production
	// Using InsecureNoChallengeStore is NOT set: we always supply a real challenge store.
	pkSvc, err := passkey.NewService(passkeyStore, passkey.Config{
		RPID:             "localhost",
		RPDisplayName:    "egauth fullstack example",
		RPOrigins:        []string{"http://localhost:8080"},
		UserVerification: protocol.VerificationRequired,
		CookieKey:        cookieKey,
		ChallengeStore:   challengeStore,
		Events:           audit,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey.NewService: %w", err)
	}

	// ------------------------------------------------------------------ HTTP mux
	mux := http.NewServeMux()

	// -- auth: identity + tokens ------------------------------------------
	//
	// Register and login handlers use WithInsecureNoOriginCheck because this
	// demo does not set up TrustedOrigins. In production, replace with:
	//   identity.WithTrustedOrigins("app.example.com")
	mux.Handle("POST /auth/register", identity.RegisterHandler[AppClaims](
		idSvc, issuer, claimsOf,
		identity.WithInsecureNoOriginCheck(),
		identity.WithCookies(cookies),
	))
	mux.Handle("POST /auth/login", identity.LoginHandler[AppClaims](
		idSvc, issuer, claimsOf,
		identity.WithInsecureNoOriginCheck(),
		identity.WithCookies(cookies),
	))
	mux.Handle("POST /auth/refresh", tokens.RefreshHandler[AppClaims](
		issuer,
		tokens.WithCookies(cookies),
		// Omit WithTrustedOrigins in this demo; a real deployment should set it.
		tokens.WithInsecureNoOriginCheck(),
	))
	mux.Handle("POST /auth/logout", tokens.LogoutHandler(
		tokenStore,
		tokens.WithCookies(cookies),
		tokens.WithInsecureNoOriginCheck(),
	))

	// -- MFA (TOTP) -------------------------------------------------------
	//
	// Mount MFA handlers behind ContextMiddleware so the authenticated user is
	// available to mfa.WithUserResolver(tokens.UserResolverFromContext) —
	// the first-party wiring adapter that reads Actor from context.
	mfaOpts := []mfa.HandlerOption{
		mfa.WithUserResolver(tokens.UserResolverFromContext),
		mfa.WithInsecureNoOriginCheck(),
	}
	mux.Handle("POST /mfa/enroll", tokens.ContextMiddleware[AppClaims](
		issuer,
		mfa.EnrollHandler(mfaSvc, mfaOpts...),
		tokens.WithCookieAuth[AppClaims](cookies),
	))
	mux.Handle("POST /mfa/confirm", tokens.ContextMiddleware[AppClaims](
		issuer,
		mfa.ConfirmHandler(mfaSvc, mfaOpts...),
		tokens.WithCookieAuth[AppClaims](cookies),
	))
	mux.Handle("POST /mfa/verify", tokens.ContextMiddleware[AppClaims](
		issuer,
		mfa.VerifyHandler(mfaSvc, mfaOpts...),
		tokens.WithCookieAuth[AppClaims](cookies),
	))

	// -- passkey ----------------------------------------------------------
	//
	// Registration requires an authenticated user; login is unauthenticated.
	// The UserResolver for registration reads the actor from context; the
	// login-success callback issues a JWT token pair.
	passkeyUserResolver := func(r *http.Request) (uuid.UUID, string, string, string, bool) {
		a, ok := tokens.ActorFromContext(r.Context())
		if !ok {
			return uuid.Nil, "", "", "", false
		}
		// name/displayName would come from your user profile in production.
		return a.UserID, a.TenantID, a.UserID.String(), a.UserID.String(), true
	}
	passkeyLoginSuccess := passkey.LoginSuccessFunc(func(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
		// Issue a JWT pair for the passkey-authenticated user.
		pair, err := issuer.IssueTokenPair(r.Context(), tokens.Claims[AppClaims]{
			Subject:  userID,
			TenantID: "",
			Custom:   AppClaims{Role: "user"},
		})
		if err != nil {
			http.Error(w, "token issuance failed", http.StatusInternalServerError)
			return
		}
		cookies.SetAccess(w, pair.AccessToken)
		cookies.SetRefresh(w, pair.RefreshToken, pair.RefreshTokenExpiresAt, false)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.Handle("POST /passkey/register/begin", tokens.ContextMiddleware[AppClaims](
		issuer,
		passkey.BeginRegistrationHandler(pkSvc,
			passkey.WithUserResolver(passkeyUserResolver),
			passkey.WithInsecureCookies(),
		),
		tokens.WithCookieAuth[AppClaims](cookies),
	))
	mux.Handle("POST /passkey/register/finish", tokens.ContextMiddleware[AppClaims](
		issuer,
		passkey.FinishRegistrationHandler(pkSvc,
			passkey.WithUserResolver(passkeyUserResolver),
			passkey.WithInsecureCookies(),
		),
		tokens.WithCookieAuth[AppClaims](cookies),
	))
	mux.Handle("POST /passkey/login/begin",
		passkey.BeginLoginHandler(pkSvc, passkey.WithInsecureCookies()),
	)
	mux.Handle("POST /passkey/login/finish",
		passkey.FinishLoginHandler(pkSvc,
			passkey.WithLoginSuccess(passkeyLoginSuccess),
			passkey.WithInsecureCookies(),
		),
	)

	// -- admin ------------------------------------------------------------
	//
	// Admin routes are protected by RequireAuth with a Role==admin check.
	// In a real app you would parse a UUID from the URL path; for brevity we
	// use a query parameter (?id=<uuid>).
	adminMiddleware := func(next func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, c AppClaims)) http.Handler {
		return tokens.RequireAuth[AppClaims](issuer,
			func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, c AppClaims) {
				if !isAdmin(claimsFromActor(r), w) {
					return
				}
				next(w, r, actor, c)
			},
			tokens.WithCookieAuth[AppClaims](cookies),
		)
	}

	mux.Handle("POST /admin/disable", adminMiddleware(
		func(w http.ResponseWriter, r *http.Request, _ egauth.Actor, _ AppClaims) {
			id, ok := parseUUIDParam(r, w)
			if !ok {
				return
			}
			if err := idSvc.DisableUser(r.Context(), "", id); err != nil {
				if errors.Is(err, identity.ErrUserNotFound) {
					http.Error(w, "user not found", http.StatusNotFound)
					return
				}
				http.Error(w, "disable failed", http.StatusInternalServerError)
				return
			}
			event.Emit(r.Context(), audit, event.Event{
				Type:   "admin.disable_user",
				UserID: id.String(),
			})
			w.WriteHeader(http.StatusNoContent)
		},
	))

	mux.Handle("POST /admin/enable", adminMiddleware(
		func(w http.ResponseWriter, r *http.Request, _ egauth.Actor, _ AppClaims) {
			id, ok := parseUUIDParam(r, w)
			if !ok {
				return
			}
			if err := idSvc.EnableUser(r.Context(), "", id); err != nil {
				if errors.Is(err, identity.ErrUserNotFound) {
					http.Error(w, "user not found", http.StatusNotFound)
					return
				}
				http.Error(w, "enable failed", http.StatusInternalServerError)
				return
			}
			event.Emit(r.Context(), audit, event.Event{
				Type:   "admin.enable_user",
				UserID: id.String(),
			})
			w.WriteHeader(http.StatusNoContent)
		},
	))

	mux.Handle("POST /admin/mfa/unlock", adminMiddleware(
		func(w http.ResponseWriter, r *http.Request, _ egauth.Actor, _ AppClaims) {
			id, ok := parseUUIDParam(r, w)
			if !ok {
				return
			}
			if err := mfaSvc.UnlockMFA(r.Context(), "", id); err != nil {
				http.Error(w, "unlock failed", http.StatusInternalServerError)
				return
			}
			event.Emit(r.Context(), audit, event.Event{
				Type:   "admin.unlock_mfa",
				UserID: id.String(),
			})
			w.WriteHeader(http.StatusNoContent)
		},
	))

	// -- protected demo route ---------------------------------------------
	mux.Handle("GET /me", tokens.RequireAuth[AppClaims](issuer,
		func(w http.ResponseWriter, r *http.Request, actor egauth.Actor, c AppClaims) {
			_, _ = fmt.Fprintf(w, "userID=%s role=%s\n", actor.UserID, c.Role)
		},
		tokens.WithCookieAuth[AppClaims](cookies),
	))

	return mux, nil
}

// claimsFromActor is a helper that extracts the token Claims from the request context so
// the admin middleware can inspect the Role without threading the generic type through
// a second argument.
func claimsFromActor(r *http.Request) *tokens.Claims[AppClaims] {
	c, ok := tokens.ClaimsFromContext[AppClaims](r.Context())
	if !ok {
		return nil
	}
	return c
}

// parseUUIDParam reads the "id" query parameter as a UUID.
func parseUUIDParam(r *http.Request, w http.ResponseWriter) (uuid.UUID, bool) {
	raw := r.URL.Query().Get("id")
	if raw == "" {
		http.Error(w, "missing id parameter", http.StatusBadRequest)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		http.Error(w, "invalid uuid", http.StatusBadRequest)
		return uuid.Nil, false
	}
	return id, true
}

func main() {
	handler, err := BuildServer()
	if err != nil {
		slog.Error("failed to build server", "err", err)
		return
	}
	addr := ":8080"
	slog.Info("egauth fullstack example listening", "addr", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		slog.Error("server stopped", "err", err)
	}
}
