package authflow

import (
	"fmt"
	"io"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output.
const redacted = "REDACTED"

// minEngineSecretLength is the documented floor for the flow-token HMAC key, kept at 16 bytes
// (128-bit) for backward compatibility. HMAC-SHA256 with a 128-bit key still provides 128-bit
// strength, and the material defect is a trivially-known or published key, which
// secretpolicy.Validate rejects at any length. secretpolicy.MinKeyLength (32) is the
// library-wide convention; raising this floor is a breaking change for existing callers.
const minEngineSecretLength = 16

// Engine holds the flow-token HMAC key in an unexported []byte field. Go's fmt prints unexported
// struct fields and renders a []byte as recoverable decimal byte values, so a %v/%+v/%#v or
// slog.Any on the engine discloses the key — and with it the ability to mint a flow token for any
// subject, which is the credential the step-up ceremony exists to withhold.
//
// The methods use value receivers on purpose (F-AFLOW-001): fmt consults Stringer only for
// string-like verbs and only through the method set of the formatted type, so a pointer-receiver
// Stringer neither covers fmt.Sprintf("%v", *engine) — fmt's reflection then prints the
// unexported secret field — nor non-string verbs such as %d on the pointer. Format below covers
// every verb; both receivers cover both forms. The non-secret configuration stays visible so a
// log line remains useful for debugging.
func (e Engine) String() string {
	return e.summary()
}

// GoString redacts the %#v representation. It uses the value receiver for the same reason as
// String; Format below takes precedence for every fmt verb.
func (e Engine) GoString() string {
	return e.summary()
}

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

// Format implements fmt.Formatter so non-string verbs (%d, %x, ...) render the redacted summary
// instead of falling back to fmt's reflection over the unexported secret field. Format lives in
// the value method set, so both Engine and *Engine are covered: fmt prefers Formatter over
// Stringer for every verb.
//
// Formatting a nil *Engine now hits fmt's panic recovery (a value receiver cannot observe a nil
// pointer): fmt prints a %!…(PANIC=…) marker without any field content. The previous
// pointer-receiver-only method set rendered "authflow.Engine(nil)" for that case.
func (e Engine) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, e.summary())
}

// summary is the shared redacted rendering used by String, GoString and Format.
func (e Engine) summary() string {
	return fmt.Sprintf(
		"authflow.Engine{Secret:%s CookieName:%s TTL:%s MFAGateSet:%t MinterSet:%t ValidatorSet:%t PasswordCheckerSet:%t InsecureCookies:%t}",
		redacted, e.cookieName, e.ttl, e.mfaGate != nil, e.minter != nil, e.validator != nil,
		e.pwChecker != nil, e.insecureCookies,
	)
}
