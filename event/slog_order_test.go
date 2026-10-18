package event_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/JLugagne/egauth/event"
)

func TestSlogSinkLogsAttributesInAStableOrder(t *testing.T) {
	line := func() string {
		var buf bytes.Buffer
		sink := event.NewSlogSink(slog.New(slog.NewTextHandler(&buf, nil)))
		sink.EmitEvent(context.Background(), event.Event{Type: event.LoginFailed, Attrs: map[string]any{
			string(event.KeyMethod): "password", string(event.KeyProvider): "corp", string(event.KeyFactor): "totp",
			string(event.KeyIdentifierKind): "email", string(event.KeyDeliveryID): "d-1",
		}})
		return buf.String()[len("time=2006-01-02T15:04:05.000Z07:00 "):]
	}
	first := line()
	for range 50 {
		if got := line(); got != first {
			t.Fatalf("one event logged as\n%s\nthen\n%s", first, got)
		}
	}
}
