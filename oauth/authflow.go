package oauth

import (
	"context"
	"net/http"

	"github.com/JLugagne/egauth/identity"
)

// AuthFlow is the seam through which the OAuth callback handlers delegate the
// post-authentication pipeline — account lifecycle validation, MFA policy enforcement,
// forced-password-change gating and final credential issuance — to a unified authentication
// flow engine (see the authflow package, issue #71 / SEC-GLO-02). It is structurally identical
// to identity.AuthFlow, so a single adapter (authflow.NewHandlerFlow) satisfies both.
//
// Contract: ProcessPrimaryAuth is called after the provider callback has been fully validated
// (state/PKCE/nonce) and the local identity linked or JIT-provisioned. The flow writes
// everything the client needs directly to w — either the final credentials (flow completed) or
// the short-lived flow-token cookie (MFA challenged, to be completed through the engine's
// step-up endpoint). A non-nil error means the flow was rejected and nothing was written.
type AuthFlow interface {
	ProcessPrimaryAuth(
		ctx context.Context,
		w http.ResponseWriter,
		r *http.Request,
		user *identity.User,
		method string,
		initialAMR []string,
		remember bool,
	) error
}

// WithAuthFlow wires a unified authentication flow engine into CallbackHandler and
// DynamicCallbackHandler. When set, an MFA-enrolled user authenticating through the provider
// does NOT receive a full access+refresh pair on the callback: the engine parks the ceremony in
// the MFA-challenged state and sets only its flow-token cookie, closing the SEC-GLO-02 bypass.
// The handler-side issuer/claims builder is bypassed entirely — the engine's SessionMinter owns
// issuance. Wrap an authflow.Engine with authflow.NewHandlerFlow to obtain an AuthFlow.
func WithAuthFlow(f AuthFlow) HandlerOption {
	return func(h *handlerConfig) { h.authFlow = f }
}
