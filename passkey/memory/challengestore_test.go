package memory_test

import (
	"context"
	"testing"
	"time"

	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChallengeStore_SingleUseConsume(t *testing.T) {
	ctx := context.Background()
	cs := passkeymemory.NewChallengeStore()

	require.NoError(t, cs.Put(ctx, "t1", "chal-A", time.Now().Add(time.Minute)))

	// First consume: present and unexpired.
	ok, err := cs.Consume(ctx, "t1", "chal-A")
	require.NoError(t, err)
	assert.True(t, ok, "first consume must report the challenge as present")

	// Second consume of the same challenge: already used.
	ok, err = cs.Consume(ctx, "t1", "chal-A")
	require.NoError(t, err)
	assert.False(t, ok, "second consume of the same challenge must report not-found")
}

func TestChallengeStore_ExpiredConsumesAsFalse(t *testing.T) {
	ctx := context.Background()
	cs := passkeymemory.NewChallengeStore()

	require.NoError(t, cs.Put(ctx, "t1", "chal-exp", time.Now().Add(-time.Second)))

	ok, err := cs.Consume(ctx, "t1", "chal-exp")
	require.NoError(t, err)
	assert.False(t, ok, "an expired challenge must consume as false")
}

func TestChallengeStore_DistinctChallengesIndependent(t *testing.T) {
	ctx := context.Background()
	cs := passkeymemory.NewChallengeStore()

	require.NoError(t, cs.Put(ctx, "t1", "chal-A", time.Now().Add(time.Minute)))
	require.NoError(t, cs.Put(ctx, "t1", "chal-B", time.Now().Add(time.Minute)))

	ok, err := cs.Consume(ctx, "t1", "chal-A")
	require.NoError(t, err)
	assert.True(t, ok)

	// Consuming A must not affect B.
	ok, err = cs.Consume(ctx, "t1", "chal-B")
	require.NoError(t, err)
	assert.True(t, ok, "distinct challenges must be independent")
}

func TestChallengeStore_TenantScoping(t *testing.T) {
	ctx := context.Background()
	cs := passkeymemory.NewChallengeStore()

	require.NoError(t, cs.Put(ctx, "t1", "same-chal", time.Now().Add(time.Minute)))

	// Same challenge string under a different tenant is a different key.
	ok, err := cs.Consume(ctx, "t2", "same-chal")
	require.NoError(t, err)
	assert.False(t, ok, "tenant scoping keeps challenges isolated per tenant")

	// The original tenant's entry is still consumable.
	ok, err = cs.Consume(ctx, "t1", "same-chal")
	require.NoError(t, err)
	assert.True(t, ok)
}
