package ratelimit_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/JLugagne/egauth/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenBucket_DefaultMaxKeys_BoundedCapacity(t *testing.T) {
	ctx := context.Background()
	tb := ratelimit.NewTokenBucket(2, time.Minute)

	assert.Equal(t, ratelimit.DefaultMaxKeys, tb.MaxKeys(), "default maxKeys should be set to DefaultMaxKeys")

	// Insert more keys than DefaultMaxKeys to verify capacity is bounded
	const extra = 5
	totalKeys := ratelimit.DefaultMaxKeys + extra
	for i := 0; i < totalKeys; i++ {
		allowed, _ := tb.Allow(ctx, "key-"+strconv.Itoa(i))
		require.True(t, allowed)
	}

	assert.Equal(t, ratelimit.DefaultMaxKeys, tb.KeyCount(), "bucket count should not exceed DefaultMaxKeys")
}

func TestTokenBucket_WithMaxKeys_InvalidValues(t *testing.T) {
	// Calling WithMaxKeys with non-positive values should use DefaultMaxKeys
	tbZero := ratelimit.NewTokenBucket(1, time.Minute, ratelimit.WithMaxKeys(0))
	assert.Equal(t, ratelimit.DefaultMaxKeys, tbZero.MaxKeys(), "WithMaxKeys(0) should fall back to DefaultMaxKeys")

	tbNeg := ratelimit.NewTokenBucket(1, time.Minute, ratelimit.WithMaxKeys(-10))
	assert.Equal(t, ratelimit.DefaultMaxKeys, tbNeg.MaxKeys(), "WithMaxKeys(negative) should fall back to DefaultMaxKeys")
}

func TestTokenBucket_ThrottledKeysNotEvictedByFlooding(t *testing.T) {
	ctx := context.Background()

	t.Run("actively throttled key is not evicted when all keys are throttled", func(t *testing.T) {
		tb := ratelimit.NewTokenBucket(1, time.Hour, ratelimit.WithMaxKeys(3))
		targetKey := "victim-throttled"

		// Exhaust the quota for targetKey
		allowed, _ := tb.Allow(ctx, targetKey)
		require.True(t, allowed)

		// Verify targetKey is throttled
		allowed, wait := tb.Allow(ctx, targetKey)
		require.False(t, allowed)
		require.Greater(t, wait, time.Minute)

		// Flood with synthetic keys to trigger eviction
		for i := 0; i < 20; i++ {
			tb.Allow(ctx, fmt.Sprintf("flood-%d", i))
		}

		// The throttled key must NOT have been evicted; it must still be rate-limited
		allowedAfterFlooding, _ := tb.Allow(ctx, targetKey)
		assert.False(t, allowedAfterFlooding, "actively throttled key must not be evicted and reset to full burst")
	})

	t.Run("unthrottled keys are preferred for eviction over throttled keys", func(t *testing.T) {
		tb := ratelimit.NewTokenBucket(5, time.Hour, ratelimit.WithMaxKeys(3))
		throttledKey := "throttled-key"

		// Exhaust all 5 tokens for throttledKey
		for i := 0; i < 5; i++ {
			allowed, _ := tb.Allow(ctx, throttledKey)
			require.True(t, allowed)
		}
		// Confirm it is throttled
		allowed, _ := tb.Allow(ctx, throttledKey)
		require.False(t, allowed)

		// Add 2 keys that only use 1 token each (tokens = 4 >= 1.0)
		allowed, _ = tb.Allow(ctx, "unthrottled-1")
		require.True(t, allowed)
		allowed, _ = tb.Allow(ctx, "unthrottled-2")
		require.True(t, allowed)

		require.Equal(t, 3, tb.KeyCount())

		// Add a new key: capacity is full, eviction must occur
		allowed, _ = tb.Allow(ctx, "unthrottled-3")
		require.True(t, allowed)

		// throttledKey must NOT have been evicted (one of unthrottled keys must have been evicted)
		allowedAfter, _ := tb.Allow(ctx, throttledKey)
		assert.False(t, allowedAfter, "throttled key must remain throttled when unthrottled keys are available for eviction")
	})
}
