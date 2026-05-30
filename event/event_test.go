package event_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/JLugagne/libauth/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmit_NilSinkIsNoop(t *testing.T) {
	// Must not panic.
	event.Emit(context.Background(), nil, event.Event{Type: event.LoginSucceeded})
}

func TestSinkFunc(t *testing.T) {
	var got event.Event
	sink := event.SinkFunc(func(_ context.Context, e event.Event) { got = e })
	event.Emit(context.Background(), sink, event.Event{Type: event.LoginFailed, Reason: "x"})
	assert.Equal(t, event.LoginFailed, got.Type)
	assert.Equal(t, "x", got.Reason)
}

func TestMultiSink_FansOut(t *testing.T) {
	var a, b int
	sink := event.MultiSink(
		event.SinkFunc(func(context.Context, event.Event) { a++ }),
		nil, // nil entries are skipped
		event.SinkFunc(func(context.Context, event.Event) { b++ }),
	)
	event.Emit(context.Background(), sink, event.Event{Type: event.UserRegistered})
	assert.Equal(t, 1, a)
	assert.Equal(t, 1, b)
}

func TestSlogSink_LevelsAndAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sink := event.NewSlogSink(logger)

	type record struct {
		Level  string `json:"level"`
		Event  string `json:"event"`
		UserID string `json:"user_id"`
		Reason string `json:"reason"`
		Error  string `json:"error"`
	}
	decodeLast := func() record {
		t.Helper()
		dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
		var last record
		for dec.More() {
			var r record
			require.NoError(t, dec.Decode(&r))
			last = r
		}
		return last
	}

	t.Run("info for ordinary events", func(t *testing.T) {
		buf.Reset()
		sink.EmitEvent(context.Background(), event.Event{Type: event.LoginSucceeded, UserID: "u1"})
		r := decodeLast()
		assert.Equal(t, "INFO", r.Level)
		assert.Equal(t, "login.succeeded", r.Event)
		assert.Equal(t, "u1", r.UserID)
	})

	t.Run("warn for failure/anomaly events", func(t *testing.T) {
		buf.Reset()
		sink.EmitEvent(context.Background(), event.Event{Type: event.LoginFailed, Reason: "invalid_credentials"})
		r := decodeLast()
		assert.Equal(t, "WARN", r.Level)
		assert.Equal(t, "invalid_credentials", r.Reason)
	})

	t.Run("error when Err is set", func(t *testing.T) {
		buf.Reset()
		sink.EmitEvent(context.Background(), event.Event{Type: event.DeliveryFailed, Err: errors.New("smtp down")})
		r := decodeLast()
		assert.Equal(t, "ERROR", r.Level)
		assert.Contains(t, r.Error, "smtp down")
	})
}

func TestNewSlogSink_NilLoggerUsesDefault(t *testing.T) {
	// Should not panic with a nil logger (falls back to slog.Default()).
	sink := event.NewSlogSink(nil)
	sink.EmitEvent(context.Background(), event.Event{Type: event.LoginSucceeded})
}
