package authflow

import (
	"fmt"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output.
const redacted = "REDACTED"

// Engine holds the flow-token HMAC key in an unexported []byte field. Go's fmt prints unexported
// struct fields and renders a []byte as recoverable decimal byte values, so a %v/%+v/%#v or
// slog.Any on the engine discloses the key — and with it the ability to mint a flow token for any
// subject, which is the credential the step-up ceremony exists to withhold.
//
// tokens/jwt.Service is redacted for exactly this reason ("fmt dumps unexported key bytes"); the
// same mitigation belongs on any type holding a key of the same kind. The methods below cover both
// the pointer and value forms and keep the non-secret configuration visible so a log line stays
// useful for debugging.
func (e *Engine) String() string {
	if e == nil {
		return "authflow.Engine(nil)"
	}
	return fmt.Sprintf(
		"authflow.Engine{Secret:%s CookieName:%s TTL:%s MFAGateSet:%t MinterSet:%t ValidatorSet:%t PasswordCheckerSet:%t InsecureCookies:%t}",
		redacted, e.cookieName, e.ttl, e.mfaGate != nil, e.minter != nil, e.validator != nil,
		e.pwChecker != nil, e.insecureCookies,
	)
}

// GoString redacts the %#v representation.
func (e *Engine) GoString() string { return e.String() }

// LogValue redacts the Engine for structured (slog) logging.
func (e *Engine) LogValue() slog.Value {
	if e == nil {
		return slog.GroupValue(slog.String("engine", "nil"))
	}
	return slog.GroupValue(
		slog.String("secret", redacted),
		slog.String("cookie_name", e.cookieName),
		slog.Duration("ttl", e.ttl),
		slog.Bool("mfa_gate_set", e.mfaGate != nil),
		slog.Bool("minter_set", e.minter != nil),
		slog.Bool("validator_set", e.validator != nil),
	)
}
