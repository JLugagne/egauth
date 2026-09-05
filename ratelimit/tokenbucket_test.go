package ratelimit_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/JLugagne/egauth/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenBucket_DefaultMaxKeys_BoundedCapacity(t *testing.T) {
	ctx := context.Background()
	tb := ratelimit.NewTokenBucket(1, time.Minute)

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
