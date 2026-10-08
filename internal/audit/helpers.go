package audit

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/principal"
)

// CredentialAdded reports a registered credential of factor f. It returns ErrInvalidArgument for
// the zero Factor.
func CredentialAdded(ctx context.Context, sink event.Sink, s Scope, f principal.Factor) error {
	return emitFactor(ctx, sink, event.CredentialAdded, s, f)
}

// CredentialRemoved reports a deleted credential of factor f. It returns ErrInvalidArgument for
// the zero Factor.
func CredentialRemoved(ctx context.Context, sink event.Sink, s Scope, f principal.Factor) error {
	return emitFactor(ctx, sink, event.CredentialRemoved, s, f)
}

// MFAVerified reports a successfully verified second factor f. It returns ErrInvalidArgument for
// the zero Factor.
func MFAVerified(ctx context.Context, sink event.Sink, s Scope, f principal.Factor) error {
	return emitFactor(ctx, sink, event.MFAVerified, s, f)
}

// MFAUnlocked reports an operator reset of a locked-out second factor.
func MFAUnlocked(ctx context.Context, sink event.Sink, s Scope) error {
	return Emit(ctx, sink, event.MFAUnlocked, s, Detail{}, nil)
}

// SystemCallerUsed reports a facade call that ran under the system caller. reason is a short
// machine code naming the call; it returns ErrInvalidArgument when reason is empty.
func SystemCallerUsed(ctx context.Context, sink event.Sink, s Scope, reason string) error {
	if reason == "" {
		return errors.Join(ErrInvalidArgument, errors.New("empty system caller reason"))
	}
	return Emit(ctx, sink, event.SystemCallerUsed, s, Detail{Reason: reason}, nil)
}

// IdentifierChanged reports a changed contact identifier of kind k. It returns ErrInvalidArgument
// for an undeclared kind.
func IdentifierChanged(ctx context.Context, sink event.Sink, s Scope, k lifecycle.IdentifierKind) error {
	switch k {
	case lifecycle.IdentifierEmail, lifecycle.IdentifierPhone, lifecycle.IdentifierRecoveryEmail:
	default:
		return errors.Join(ErrInvalidArgument, errors.New("undeclared identifier kind"))
	}
	return Emit(ctx, sink, event.IdentifierChanged, s, Detail{}, nil, A(event.KeyIdentifierKind, k.String()))
}

func emitFactor(ctx context.Context, sink event.Sink, t event.Type, s Scope, f principal.Factor) error {
	code := f.Code()
	if code == "" {
		return errors.Join(ErrInvalidArgument, errors.New("zero factor"))
	}
	return Emit(ctx, sink, t, s, Detail{}, nil, A(event.KeyFactor, code))
}
