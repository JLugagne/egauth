package jwt_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *captureSink) EmitEvent(_ context.Context, e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) has(t event.Type) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Type == t {
			return true
		}
	}
	return false
}

func TestJWTEvents_ReuseDetectedAndFamilyRevoked(t *testing.T) {
	ctx := context.Background()
	sink := &captureSink{}
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:            memory.NewStore[struct{}](),
		SecretKey:        "rotation-secret-aaaaaaaaaaaaaaaaaaaaaaaa",
		Issuer:           "egauth-test",
		AccessTTL:        5 * time.Minute,
		RefreshTTL:       24 * time.Hour,
		ClaimsProvider:   okProvider(t),
		ReuseGracePeriod: -1, // strict: any replay of a consumed token revokes the family
		EventSink:        sink,
	})

	pair, err := svc.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: uuid.New()})
	require.NoError(t, err)

	// First rotation consumes the token.
	_, err = svc.Rotate(ctx, pair.RefreshToken)
	require.NoError(t, err)

	// Replaying the now-consumed token is treated as theft (strict mode): reuse detected and the
	// family revoked.
	_, err = svc.Rotate(ctx, pair.RefreshToken)
	require.ErrorIs(t, err, tokens.ErrRefreshTokenReused)
	assert.True(t, sink.has(event.RefreshReuseDetected), "a replayed consumed token must emit RefreshReuseDetected")
	assert.True(t, sink.has(event.TokenFamilyRevoked), "strict-mode reuse must emit TokenFamilyRevoked")
}
