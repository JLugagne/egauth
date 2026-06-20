package event_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/JLugagne/egauth/event"
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

func TestAPIKeyEventTypes(t *testing.T) {
	// Verify all four API-key Type constants have the expected string values.
	assert.Equal(t, event.Type("api_key.created"), event.APIKeyCreated)
	assert.Equal(t, event.Type("api_key.auth.succeeded"), event.APIKeyAuthSucceeded)
	assert.Equal(t, event.Type("api_key.auth.failed"), event.APIKeyAuthFailed)
	assert.Equal(t, event.Type("api_key.purged"), event.APIKeyPurged)

	// Verify the Reason code constants.
	assert.Equal(t, "not_found", event.ReasonAPIKeyNotFound)
	assert.Equal(t, "expired", event.ReasonAPIKeyExpired)
	assert.Equal(t, "tenant_mismatch", event.ReasonAPIKeyTenantMismatch)
	assert.Equal(t, "wrong_type", event.ReasonAPIKeyWrongType)
}

func TestAPIKeyAuthFailed_LogsAtWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sink := event.NewSlogSink(logger)

	type record struct {
		Level  string `json:"level"`
		Event  string `json:"event"`
		Reason string `json:"reason"`
	}

	for _, reason := range []string{
		event.ReasonAPIKeyNotFound,
		event.ReasonAPIKeyExpired,
		event.ReasonAPIKeyTenantMismatch,
		event.ReasonAPIKeyWrongType,
	} {
		buf.Reset()
		sink.EmitEvent(context.Background(), event.Event{
			Type:   event.APIKeyAuthFailed,
			Reason: reason,
		})
		var r record
		require.NoError(t, json.NewDecoder(&buf).Decode(&r))
		assert.Equal(t, "WARN", r.Level, "reason=%s should log at WARN", reason)
		assert.Equal(t, "api_key.auth.failed", r.Event)
		assert.Equal(t, reason, r.Reason)
	}
}

func TestAPIKeyInfoEvents_LogAtInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sink := event.NewSlogSink(logger)

	type record struct {
		Level string `json:"level"`
		Event string `json:"event"`
	}

	for _, typ := range []event.Type{event.APIKeyCreated, event.APIKeyAuthSucceeded, event.APIKeyPurged} {
		buf.Reset()
		sink.EmitEvent(context.Background(), event.Event{Type: typ})
		var r record
		require.NoError(t, json.NewDecoder(&buf).Decode(&r))
		assert.Equal(t, "INFO", r.Level, "type=%s should log at INFO", typ)
		assert.Equal(t, string(typ), r.Event)
	}
}
