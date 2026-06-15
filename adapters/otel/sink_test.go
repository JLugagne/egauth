package otel_test

import (
	"context"
	"errors"
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
	assertAttr(t, attrs, "egauth.user_id", "user-abc")
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
	tracer := tp.Tracer("test")
	sink := egauthotel.NewSpanSink(tracer)

	sink.EmitEvent(context.Background(), event.Event{
		Type:  event.LoginFailed,
		Attrs: map[string]any{"ip": "192.0.2.1", "attempt": 3},
	})

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	attrs := attrMap(spans[0].Attributes())
	// Extra attrs are emitted as "egauth.<key>"
	if _, ok := attrs["egauth.ip"]; !ok {
		t.Error("expected egauth.ip attribute")
	}
	if _, ok := attrs["egauth.attempt"]; !ok {
		t.Error("expected egauth.attempt attribute")
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
