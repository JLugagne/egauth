package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/principal"
)

type recorder struct{ got []event.Event }

func (r *recorder) EmitEvent(_ context.Context, e event.Event) { r.got = append(r.got, e) }

func TestEmitRejectsUnregisteredKey(t *testing.T) {
	r := &recorder{}
	err := audit.Emit(context.Background(), r, event.LoginFailed, audit.Scope{}, audit.Detail{}, nil,
		audit.A(event.KeyMethod, "password"), audit.A(event.AttrKey("rogue"), "x"))
	if !errors.Is(err, audit.ErrUnregisteredKey) {
		t.Fatalf("err = %v", err)
	}
	if len(r.got) != 0 {
		t.Fatal("an event with an unregistered key must not be emitted")
	}
}

func TestEmitNeverExportsSecretAttributes(t *testing.T) {
	r := &recorder{}
	err := audit.Emit(context.Background(), r, event.LoginFailed, audit.Scope{TenantID: "t", UserID: "u"}, audit.Detail{Reason: "r"}, nil,
		audit.A(event.KeyCaptchaToken, "tok-secret"), audit.A(event.KeyIP, "192.0.2.1"), audit.A(event.KeyMethod, "a"), audit.A(event.KeyMethod, "b"))
	if err != nil || len(r.got) != 1 {
		t.Fatalf("err=%v events=%d", err, len(r.got))
	}
	e := r.got[0]
	if _, ok := e.Attrs[string(event.KeyCaptchaToken)]; ok {
		t.Fatal("secret attribute reached the sink")
	}
	if e.Attrs[string(event.KeyIP)] != "192.0.2.1" || e.Attrs[string(event.KeyMethod)] != "b" || len(e.Attrs) != 2 {
		t.Fatalf("attrs = %v", e.Attrs)
	}
	if e.TenantID != "t" || e.UserID != "u" || e.Reason != "r" || e.Type != event.LoginFailed {
		t.Fatalf("event = %+v", e)
	}
}

func TestEmitNilSinkAndPanickingSink(t *testing.T) {
	if err := audit.Emit(context.Background(), nil, event.LoginFailed, audit.Scope{}, audit.Detail{}, nil); err != nil {
		t.Fatal(err)
	}
	boom := event.SinkFunc(func(context.Context, event.Event) { panic("boom") })
	if err := audit.Emit(context.Background(), boom, event.LoginFailed, audit.Scope{}, audit.Detail{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestHelpersEmitTheirTypes(t *testing.T) {
	r := &recorder{}
	ctx, s := context.Background(), audit.Scope{TenantID: "t", UserID: "u"}
	for _, err := range []error{
		audit.CredentialAdded(ctx, r, s, principal.FactorPasskey), audit.CredentialRemoved(ctx, r, s, principal.FactorPasskey),
		audit.MFAVerified(ctx, r, s, principal.FactorTOTP), audit.MFAUnlocked(ctx, r, s),
		audit.SystemCallerUsed(ctx, r, s, "janitor"), audit.IdentifierChanged(ctx, r, s, lifecycle.IdentifierEmail),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []event.Type{event.CredentialAdded, event.CredentialRemoved, event.MFAVerified, event.MFAUnlocked, event.SystemCallerUsed, event.IdentifierChanged}
	if len(r.got) != len(want) {
		t.Fatalf("got %d events", len(r.got))
	}
	for i, w := range want {
		if r.got[i].Type != w {
			t.Errorf("event %d = %s, want %s", i, r.got[i].Type, w)
		}
	}
	if r.got[4].Reason != "janitor" || r.got[5].Attrs[string(event.KeyIdentifierKind)] != "email" {
		t.Fatalf("helper payloads wrong: %+v %+v", r.got[4], r.got[5])
	}
}

func TestEmitValidatesKeysBeforeTheNilSinkShortcut(t *testing.T) {
	err := audit.Emit(context.Background(), nil, event.LoginFailed, audit.Scope{}, audit.Detail{}, nil, audit.A(event.AttrKey("rogue"), "x"))
	if !errors.Is(err, audit.ErrUnregisteredKey) {
		t.Fatalf("err = %v, want ErrUnregisteredKey even with a nil sink", err)
	}
}

func TestHelpersRejectZeroDomainValues(t *testing.T) {
	r := &recorder{}
	ctx := context.Background()
	for name, err := range map[string]error{
		"zero factor":        audit.CredentialAdded(ctx, r, audit.Scope{}, principal.Factor{}),
		"undeclared kind":    audit.IdentifierChanged(ctx, r, audit.Scope{}, lifecycle.IdentifierKind(0)),
		"empty system cause": audit.SystemCallerUsed(ctx, r, audit.Scope{}, ""),
	} {
		if !errors.Is(err, audit.ErrInvalidArgument) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if len(r.got) != 0 {
		t.Fatalf("invalid helper calls emitted %d events", len(r.got))
	}
}

func TestEmitCarriesCauseAndRecordsFactorCode(t *testing.T) {
	r := &recorder{}
	cause := errors.New("smtp down")
	if err := audit.Emit(context.Background(), r, event.DeliveryFailed, audit.Scope{}, audit.Detail{Reason: "smtp"}, cause); err != nil {
		t.Fatal(err)
	}
	if err := audit.MFAVerified(context.Background(), r, audit.Scope{}, principal.FactorTOTP); err != nil {
		t.Fatal(err)
	}
	if r.got[0].Err.Text() != cause.Error() || r.got[0].Err.Type() != "*errors.errorString" {
		t.Fatalf("cause lost: %+v", r.got[0])
	}
	if r.got[1].Attrs[string(event.KeyFactor)] != principal.FactorTOTP.Code() {
		t.Fatalf("factor attr = %v", r.got[1].Attrs)
	}
}
