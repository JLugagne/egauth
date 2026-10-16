// Package audit is the only library emitter of events: it validates attribute keys against the
// event registry before an event reaches any sink. A guard test rejects any other library package
// that calls event.Emit, Sink.EmitEvent or builds an event.Event.
package audit

import (
	"context"
	"errors"
	"log/slog"

	"github.com/JLugagne/egauth/event"
)

// ErrUnregisteredKey is returned by Emit for an attribute key missing from the event registry.
var ErrUnregisteredKey = errors.New("audit: attribute key is not registered")

// ErrInvalidArgument is returned by a typed helper given a zero or undeclared domain value.
var ErrInvalidArgument = errors.New("audit: invalid helper argument")

// Scope identifies whom an event concerns. Empty fields are omitted.
type Scope struct {
	TenantID string
	UserID   string
}

// Attr is one attribute of an audit event; build it with A.
type Attr struct {
	key   event.AttrKey
	value any
}

// A pairs a registered key with its value.
func A(key event.AttrKey, value any) Attr { return Attr{key: key, value: value} }

// Detail carries the optional outcome fields of an event.
type Detail struct {
	// Reason is a short machine code; it must not carry secrets or raw user input.
	Reason string
}

// Emit validates attrs, then delivers one event to sink; a nil sink only validates. cause is the
// underlying failure of an outage event, nil otherwise. It returns ErrUnregisteredKey, joined
// with the offending key, and emits nothing when any attribute key is unregistered. Attributes
// classified Secret are removed before delivery and never reach the sink. A later attribute
// overrides an earlier one with the same key. A panicking sink is recovered and logged.
func Emit(ctx context.Context, sink event.Sink, t event.Type, s Scope, d Detail, cause error, attrs ...Attr) error {
	var m map[string]any
	for _, a := range attrs {
		if !a.key.Registered() {
			return errors.Join(ErrUnregisteredKey, errors.New("key "+string(a.key)))
		}
		if a.key.Sensitivity() == event.Secret {
			continue
		}
		if m == nil {
			m = make(map[string]any, len(attrs))
		}
		m[string(a.key)] = a.value
	}
	if sink == nil {
		return nil
	}
	deliver(ctx, sink, event.Event{
		Type: t, TenantID: s.TenantID, UserID: s.UserID, Reason: d.Reason, Err: event.CauseOf(cause), Attrs: m,
	})
	return nil
}

func deliver(ctx context.Context, sink event.Sink, e event.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Default().Error("egauth: event sink panicked", "event", string(e.Type), "panic", r)
		}
	}()
	sink.EmitEvent(ctx, e)
}
