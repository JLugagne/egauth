package identity

import (
	"context"
	"net/http"
)

// AuthFlow is the seam through which identity's login handlers delegate the post-credential
// pipeline — account lifecycle validation, MFA policy enforcement, forced-password-change
// gating and final credential issuance — to a unified authentication flow engine (see the
// authflow package, issue #71). The interface is defined here, rather than importing authflow,
// because authflow depends on identity: the seam keeps the dependency direction acyclic, the
// same convention as MFAEnrollmentChecker.
//
// Contract: ProcessPrimaryAuth is called after the primary credential has been verified (the
// magic-link token consumed, the OAuth code exchanged and the identity linked). The flow writes
// everything the client needs directly to w — either the final credentials (flow completed) or
// the short-lived flow-token cookie (MFA challenged, to be completed through the engine's
// step-up endpoint). A non-nil error means the flow was rejected and nothing was written.
type AuthFlow interface {
	ProcessPrimaryAuth(
		ctx context.Context,
		w http.ResponseWriter,
		r *http.Request,
		user *User,
		method string,
		initialAMR []string,
		remember bool,
	) error
}

// WithAuthFlow wires a unified authentication flow engine into MagicLinkLoginHandler. When set,
// the handler delegates every post-credential decision (account state, MFA policy, must-change
// flag, credential issuance) to the flow and bypasses its own issuer/claims builder entirely —
// the engine's SessionMinter owns issuance. Wrap an authflow.Engine with
// authflow.NewHandlerFlow to obtain an AuthFlow.
//
// Precedence: WithAuthFlow wins over WithMFAGate on the same handler — the engine has its own
// MFA gate, account validator and password-policy checker, so the handler-level gate is not
// consulted. LoginHandler and ChangePasswordWithReissueHandler keep the native
// WithMFAGate interim-token model and do not consume this option.
func WithAuthFlow(f AuthFlow) HandlerOption {
	return func(h *handlerConfig) { h.authFlow = f }
}
