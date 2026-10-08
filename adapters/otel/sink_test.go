package otel_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/JLugagne/egauth/event"

	egauthotel "github.com/JLugagne/egauth/adapters/otel"
)

// newRecorder returns an in-memory span recorder and a tracer backed by it, so
// tests can inspect spans without standing up a real OTel collector.
func newRecorder() (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	return rec, tp
}

func TestNewSpanSink_ImplementsSink(t *testing.T) {
	var _ event.Sink = egauthotel.NewSpanSink(nil)
}

func TestSpanSink_EmitsSpanPerEvent(t *testing.T) {
	rec, tp := newRecorder()
	tracer := tp.Tracer("test")
	sink := egauthotel.NewSpanSink(tracer)

	sink.EmitEvent(context.Background(), event.Event{
		Type:     event.LoginSucceeded,
		TenantID: "tenant-1",
		UserID:   "user-abc",
	})

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Name() != "egauth.login.succeeded" {
		t.Errorf("span name = %q, want %q", s.Name(), "egauth.login.succeeded")
	}
	attrs := attrMap(s.Attributes())
	assertAttr(t, attrs, "egauth.event.type", "login.succeeded")
	assertAttr(t, attrs, "egauth.tenant_id", "tenant-1")
	if _, ok := attrs["egauth.user_id"]; ok {
		t.Error("user id must not be exported without ExportPII")
	}
}

func TestSpanSink_ErrorSetsStatusAndRecordsError(t *testing.T) {
	rec, tp := newRecorder()
	tracer := tp.Tracer("test")
	sink := egauthotel.NewSpanSink(tracer)
	sentinel := errors.New("delivery failure")

	sink.EmitEvent(context.Background(), event.Event{
		Type:   event.DeliveryFailed,
		Reason: "smtp_timeout",
		Err:    sentinel,
	})

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Status().Code != codes.Error {
		t.Errorf("span status = %v, want Error", s.Status().Code)
	}
	if len(s.Events()) == 0 {
		t.Error("expected at least one span event (from RecordError), got none")
	}
	attrs := attrMap(s.Attributes())
	assertAttr(t, attrs, "egauth.reason", "smtp_timeout")
}

func TestSpanSink_NilTracer_IsNoop(t *testing.T) {
	// Must not panic.
	sink := egauthotel.NewSpanSink(nil)
	sink.EmitEvent(context.Background(), event.Event{Type: event.MFAEnrolled})
}

func TestSpanSink_SecurityEventMapping(t *testing.T) {
	// Verify a representative set of security-relevant event types produce spans
	// with the expected span name pattern (egauth.<event.Type value>).
	securityEvents := []struct {
		evt      event.Event
		wantName string
	}{
		{event.Event{Type: event.LoginFailed, Reason: "invalid_credentials"}, "egauth.login.failed"},
		{event.Event{Type: event.AccountLocked}, "egauth.account.locked"},
		{event.Event{Type: event.RefreshReuseDetected}, "egauth.refresh.reuse_detected"},
		{event.Event{Type: event.TokenFamilyRevoked}, "egauth.token.family_revoked"},
		{event.Event{Type: event.MFAVerificationFailed}, "egauth.mfa.verification_failed"},
		{event.Event{Type: event.InsecureCookieMisuse}, "egauth.cookies.insecure_misuse"},
		{event.Event{Type: event.AccountBlocked}, "egauth.account.blocked"},
	}

	for _, tc := range securityEvents {
		t.Run(string(tc.evt.Type), func(t *testing.T) {
			rec, tp := newRecorder()
			tracer := tp.Tracer("test")
			sink := egauthotel.NewSpanSink(tracer)
			sink.EmitEvent(context.Background(), tc.evt)
			spans := rec.Ended()
			if len(spans) != 1 {
				t.Fatalf("expected 1 span, got %d", len(spans))
			}
			if spans[0].Name() != tc.wantName {
				t.Errorf("span name = %q, want %q", spans[0].Name(), tc.wantName)
			}
		})
	}
}

func TestSpanSink_ExtraAttrs(t *testing.T) {
	rec, tp := newRecorder()
	sink := egauthotel.NewSpanSink(tp.Tracer("test"))

	sink.EmitEvent(context.Background(), event.Event{
		Type:  event.LoginFailed,
		Attrs: map[string]any{"ip": "192.0.2.1", "attempt": 3, "method": "password"},
	})

	attrs := attrMap(rec.Ended()[0].Attributes())
	assertAttr(t, attrs, "egauth.method", "password")
	for _, k := range []string{"egauth.ip", "egauth.attempt"} {
		if _, ok := attrs[k]; ok {
			t.Errorf("%s must be dropped", k)
		}
	}
}

func newSink(t *testing.T, o egauthotel.Options) (*tracetest.SpanRecorder, event.Sink) {
	t.Helper()
	rec, tp := newRecorder()
	sink, err := egauthotel.NewSink(tp, o)
	if err != nil {
		t.Fatal(err)
	}
	return rec, sink
}

func TestNewSink_RequiresProvider(t *testing.T) {
	if _, err := egauthotel.NewSink(nil, egauthotel.Options{}); !errors.Is(err, egauthotel.ErrNilTracerProvider) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewSink_StatusFollowsSeverity(t *testing.T) {
	for typ, want := range map[event.Type]codes.Code{
		event.LoginSucceeded:    codes.Unset,
		event.IdentifierChanged: codes.Unset,
		event.LoginFailed:       codes.Error,
		event.SystemCallerUsed:  codes.Error,
		event.MountMismatch:     codes.Error,
	} {
		rec, sink := newSink(t, egauthotel.Options{})
		sink.EmitEvent(context.Background(), event.Event{Type: typ})
		if got := rec.Ended()[0].Status().Code; got != want {
			t.Errorf("%s: status %v, want %v", typ, got, want)
		}
	}
}

func TestNewSink_DropsPIIAndSecretsByDefault(t *testing.T) {
	rec, sink := newSink(t, egauthotel.Options{})
	sink.EmitEvent(context.Background(), event.Event{
		Type: event.LoginFailed, UserID: "u-1", TenantID: "t-1", Err: errors.New("mailbox jane@example.com"),
		Attrs: map[string]any{
			string(event.KeyMethod): "password", string(event.KeyIP): "192.0.2.1",
			string(event.KeyCaptchaToken): "tok-secret", "rogue": "x",
		},
	})
	s := rec.Ended()[0]
	attrs := attrMap(s.Attributes())
	assertAttr(t, attrs, "egauth.method", "password")
	assertAttr(t, attrs, "egauth.tenant_id", "t-1")
	for _, k := range []string{"egauth.ip", "egauth.captcha_token", "egauth.rogue", "egauth.user_id"} {
		if _, ok := attrs[k]; ok {
			t.Errorf("%s exported", k)
		}
	}
	if strings.Contains(s.Status().Description, "jane@example.com") {
		t.Error("error text leaked into the status")
	}
	for _, ev := range s.Events() {
		for _, kv := range ev.Attributes {
			if strings.Contains(kv.Value.Emit(), "jane@example.com") {
				t.Error("error text leaked into a span event")
			}
		}
	}
}

func TestNewSink_ExportPIIKeepsPIINeverSecrets(t *testing.T) {
	rec, sink := newSink(t, egauthotel.Options{ExportPII: true})
	sink.EmitEvent(context.Background(), event.Event{
		Type: event.LoginFailed, UserID: "u-1",
		Attrs: map[string]any{
			string(event.KeyIP): "192.0.2.1", string(event.KeyCaptchaToken): "tok-secret", "rogue": "x",
		},
	})
	attrs := attrMap(rec.Ended()[0].Attributes())
	assertAttr(t, attrs, "egauth.ip", "192.0.2.1")
	assertAttr(t, attrs, "egauth.user_id", "u-1")
	for _, k := range []string{"egauth.captcha_token", "egauth.rogue"} {
		if _, ok := attrs[k]; ok {
			t.Errorf("%s exported", k)
		}
	}
}

// attrMap converts a slice of attribute.KeyValue to a map for easy lookup in tests.
func attrMap(kvs []attribute.KeyValue) map[string]string {
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value.AsString()
	}
	return m
}

func assertAttr(t *testing.T, attrs map[string]string, key, want string) {
	t.Helper()
	got, ok := attrs[key]
	if !ok {
		t.Errorf("missing attribute %q", key)
		return
	}
	if got != want {
		t.Errorf("attribute %q = %q, want %q", key, got, want)
	}
}
