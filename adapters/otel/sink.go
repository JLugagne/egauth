// Package otel provides an OpenTelemetry tracing adapter for egauth's event.Sink seam.
//
// NewSpanSink returns a [event.Sink] that creates one OpenTelemetry span per security event.
// Wiring it alongside [event.MultiSink] and the existing [event.NewSlogSink] gives both
// structured logging and distributed traces from a single call site.
//
// Usage:
//
//	import (
//	    "go.opentelemetry.io/otel"
//	    egauthotel "github.com/JLugagne/egauth/adapters/otel"
//	    "github.com/JLugagne/egauth/event"
//	)
//
//	tracer := otel.Tracer("egauth")
//	sink   := egauthotel.NewSpanSink(tracer)
//
//	// Fan out to both slog and spans:
//	combined := event.MultiSink(event.NewSlogSink(nil), sink)
package otel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/JLugagne/egauth/event"
)

// spanSink implements event.Sink by recording each egauth security event as a child
// OpenTelemetry span. Spans are ended immediately; the caller's span (if any) remains active.
type spanSink struct {
	tracer trace.Tracer
}

// NewSpanSink returns an [event.Sink] that records each security event as a child
// OpenTelemetry span under the span already present in ctx (or as a root span when none).
//
// The returned sink is safe for concurrent use. Spans are ended synchronously inside
// EmitEvent, so no goroutine is spawned. If tracer is nil, [noop.NewTracerProvider]
// is used (all spans become no-ops).
func NewSpanSink(tracer trace.Tracer) event.Sink {
	if tracer == nil {
		tracer = noop.NewTracerProvider().Tracer("")
	}
	return &spanSink{tracer: tracer}
}

// EmitEvent implements event.Sink.
func (s *spanSink) EmitEvent(ctx context.Context, e event.Event) {
	spanName := "egauth." + string(e.Type)
	_, span := s.tracer.Start(ctx, spanName)
	defer span.End()

	attrs := make([]attribute.KeyValue, 0, 5+len(e.Attrs))
	attrs = append(attrs, attribute.String("egauth.event.type", string(e.Type)))
	if e.TenantID != "" {
		attrs = append(attrs, attribute.String("egauth.tenant_id", e.TenantID))
	}
	if e.UserID != "" {
		attrs = append(attrs, attribute.String("egauth.user_id", e.UserID))
	}
	if e.Reason != "" {
		attrs = append(attrs, attribute.String("egauth.reason", e.Reason))
	}
	for k, v := range e.Attrs {
		attrs = append(attrs, attribute.String("egauth."+k, fmt.Sprintf("%v", v)))
	}
	span.SetAttributes(attrs...)

	if e.Err != nil {
		span.RecordError(e.Err)
		span.SetStatus(codes.Error, e.Err.Error())
	}
}
