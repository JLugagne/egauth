// Package otel provides an OpenTelemetry tracing adapter for egauth's event.Sink seam.
//
// NewSink returns an [event.Sink] that creates one OpenTelemetry span per security event.
// Only public attributes are exported; PII needs Options.ExportPII, and the sink must then be
// installed directly, because [event.MultiSink] already reduces events to public attributes.
//
// Usage:
//
//	sink, err := egauthotel.NewSink(tp, egauthotel.Options{})
//	if err != nil {
//	    return err
//	}
//	combined := event.MultiSink(event.NewSlogSink(nil), sink)
//
// # Stability
//
// Stability class: frozen-v1 candidate. The exported API is intended to remain
// backward-compatible for the life of v1; breaking changes require a new major version. Until v1
// is tagged the API remains pre-1.0. See docs/adr/0001-v1-scope-and-stability-classes.md.
package otel

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/JLugagne/egauth/event"
)

const tracerName = "github.com/JLugagne/egauth/adapters/otel"

// ErrNilTracerProvider is returned by NewSink when no TracerProvider is supplied.
var ErrNilTracerProvider = errors.New("otel: a TracerProvider is required")

// Options is the configuration of NewSink. Its zero value exports public data only.
type Options struct {
	// ExportPII also exports attributes classified PII, the user id and the text of Event.Err.
	// Secret and unregistered attributes are never exported. Leave false unless the trace
	// backend is cleared to hold personal data.
	ExportPII bool
}

type spanSink struct {
	tracer trace.Tracer
	pii    bool
}

// NewSink returns an [event.Sink] that records each security event as a span under the span
// already present in ctx (or as a root span when none). The span status is Error when the
// event Severity is Warn or higher, or when it carries an Err. Only Event.PublicAttrs are
// exported unless o.ExportPII is set. It returns ErrNilTracerProvider when tp is nil. The
// sink is safe for concurrent use; spans end synchronously.
func NewSink(tp trace.TracerProvider, o Options) (event.Sink, error) {
	if tp == nil {
		return nil, ErrNilTracerProvider
	}
	return &spanSink{tracer: tp.Tracer(tracerName), pii: o.ExportPII}, nil
}

// NewSpanSink returns a sink on tracer that exports public attributes only.
//
// Deprecated: use NewSink, which takes a TracerProvider and Options.
func NewSpanSink(tracer trace.Tracer) event.Sink {
	if tracer == nil {
		tracer = noop.NewTracerProvider().Tracer("")
	}
	return &spanSink{tracer: tracer}
}

// EmitEvent implements event.Sink.
func (s *spanSink) EmitEvent(ctx context.Context, e event.Event) {
	_, span := s.tracer.Start(ctx, "egauth."+string(e.Type))
	defer span.End()

	attrs := make([]attribute.KeyValue, 0, 5+len(e.Attrs))
	attrs = append(attrs, attribute.String("egauth.event.type", string(e.Type)),
		attribute.String("egauth.event.severity", e.Type.Severity().String()))
	if e.TenantID != "" {
		attrs = append(attrs, attribute.String("egauth.tenant_id", e.TenantID))
	}
	if e.UserID != "" && s.pii {
		attrs = append(attrs, attribute.String("egauth.user_id", e.UserID))
	}
	if e.Reason != "" {
		attrs = append(attrs, attribute.String("egauth.reason", e.Reason))
	}
	for k, v := range s.exported(e) {
		attrs = append(attrs, attribute.String("egauth."+k, fmt.Sprintf("%v", v)))
	}
	span.SetAttributes(attrs...)

	if e.Type.Severity() >= event.SeverityWarn || !e.Err.IsZero() {
		span.SetStatus(codes.Error, statusText(e))
	}
	if !e.Err.IsZero() {
		exc := []attribute.KeyValue{attribute.String("exception.type", e.Err.Type())}
		if s.pii {
			exc = append(exc, attribute.String("exception.message", e.Err.Text()))
		}
		span.AddEvent("exception", trace.WithAttributes(exc...))
	}
}

func (s *spanSink) exported(e event.Event) map[string]any {
	if s.pii {
		return e.AttrsUpTo(event.PII)
	}
	return e.PublicAttrs()
}

func statusText(e event.Event) string {
	if e.Reason != "" {
		return e.Reason
	}
	return string(e.Type)
}
