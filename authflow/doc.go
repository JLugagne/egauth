// Package authflow provides a unified authentication state machine (Auth Flow Engine) that
// coordinates the full authentication ceremony — identity resolution, account lifecycle
// validation, MFA policy enforcement, compliance gating, and final credential issuance —
// through a single pipeline, regardless of the primary authentication method (password,
// OAuth/OIDC, magic link, passkey/WebAuthn).
//
// # Motivation
//
// Prior to authflow, each authentication handler independently validated credentials, checked
// account status, evaluated MFA policies, and minted tokens or sessions. This siloing caused:
//
//   - MFA bypass via magic link and OAuth logins (SEC-ID-03, SEC-GLO-02)
//   - Inconsistent account lifecycle checks across handlers (SEC-ID-12)
//   - Hardcoded AMR claims in MFA step-up (SEC-MFA-01)
//   - Coupling to stateless JWTs — no way to issue stateful sessions
//
// The Engine centralizes these decisions, ensuring every login path enforces the same rules.
//
// # Flow States
//
//   - StateInitial: flow created, primary factor not yet evaluated
//   - StateMFAChallenged: primary factor verified, awaiting second factor
//   - StateCompleted: all gates passed, credentials issued
//   - StateRejected: flow denied (disabled account, expired token, etc.)
//
// # Usage
//
//	engine, _ := authflow.NewEngine(secret,
//	    authflow.WithMFAGate(mfaSvc),
//	    authflow.WithMinter(authflow.NewJWTMinter(issuer, claimsOf, cookies, false)),
//	    authflow.WithAccountValidator(authflow.NewIdentityAccountValidator(store)),
//	)
//
//	// In any login handler (password, OAuth, passkey, magic link):
//	result, err := engine.ProcessPrimaryAuth(ctx, w, r, user, "password", []string{"pwd"}, false)
//	if result.State == authflow.StateMFAChallenged {
//	    // Return flow token to client; wait for MFA step-up
//	}
//
//	// In MFA step-up handler:
//	result, err := engine.ProcessStepUp(ctx, w, r, flowToken, "totp", []string{"otp"})
//
// # Integration With The Shipped Handlers
//
// The engine is not a separate login route — it plugs into the existing identity and oauth
// handlers so every primary method shares one pipeline. NewHandlerFlow wraps an Engine to
// satisfy the single-method seam those packages define (identity.AuthFlow and oauth.AuthFlow are
// structurally identical). Wiring it is one option per handler:
//
//	flow := authflow.NewHandlerFlow(engine)
//
//	// Magic-link login now enforces the engine's MFA/account/change gates (SEC-ID-03):
//	mux.Handle("POST /auth/magic-link/login",
//	    identity.MagicLinkLoginHandler[struct{}](idSvc, issuer, claimsOf, identity.WithAuthFlow(flow)))
//
//	// The OAuth callback no longer mints a full pair for an MFA-enrolled user (SEC-GLO-02):
//	mux.Handle("GET /auth/oauth/callback",
//	    oauth.CallbackHandler[struct{}](provider, idSvc, issuer, claimsOf, oauth.WithAuthFlow(flow)))
//
// When the flow is challenged, these handlers write only the engine's flow-token cookie and no
// access/refresh cookie. The client completes the ceremony by POSTing the second-factor code to
// StepUpHandler, which verifies the code with a FactorVerifier (mfa.Service satisfies it
// directly), then drives Engine.ProcessStepUp to mint the final credentials and clear the flow
// cookie:
//
//	mux.Handle("POST /auth/mfa/step-up", authflow.StepUpHandler(engine, mfaSvc))
//
// # Second Factor Without The Engine
//
// MagicLinkLoginHandler also honors identity.WithMFAGate on its own, using the same interim-token
// model as identity.LoginHandler (short-lived access token, no refresh cookie) completed through
// mfa.StepUpHandler. Choose that lighter path when you want MFA gating without adopting the full
// flow-token engine; choose WithAuthFlow when you want every login method to share one pipeline.
package authflow
