package storetest

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ChallengeStoreContractTesting exercises any passkey.ChallengeStore implementation for the
// single-use, TTL-bounded, tenant-scoped semantics the replay defence (SEC-05) depends on. Both the
// in-memory reference store and the Postgres-backed one are pinned by this suite, so a deployment
// can swap backends without changing the security properties.
//
// The store must be empty of the challenge names used below; each subtest uses its own prefix so a
// shared backend can run the suite repeatedly.
func ChallengeStoreContractTesting(t *testing.T, cs passkey.ChallengeStore) {
	ctx := context.Background()

	t.Run("single-use consume", func(t *testing.T) {
		require.NoError(t, cs.Put(ctx, "tenant-A", "contract-single-use", time.Now().Add(time.Minute)))

		ok, err := cs.Consume(ctx, "tenant-A", "contract-single-use")
		require.NoError(t, err)
		assert.True(t, ok, "the first consume must report the challenge as present")

		ok, err = cs.Consume(ctx, "tenant-A", "contract-single-use")
		require.NoError(t, err)
		assert.False(t, ok, "a second consume of the same challenge must report not-found")
	})

	t.Run("unknown challenge", func(t *testing.T) {
		ok, err := cs.Consume(ctx, "tenant-A", "contract-never-issued")
		require.NoError(t, err)
		assert.False(t, ok, "a challenge that was never issued must not consume")
	})

	t.Run("expired challenge", func(t *testing.T) {
		require.NoError(t, cs.Put(ctx, "tenant-A", "contract-expired", time.Now().Add(-time.Second)))

		ok, err := cs.Consume(ctx, "tenant-A", "contract-expired")
		require.NoError(t, err)
		assert.False(t, ok, "an expired challenge must consume as false")

		ok, err = cs.Consume(ctx, "tenant-A", "contract-expired")
		require.NoError(t, err)
		assert.False(t, ok, "an expired challenge must stay unusable")
	})

	t.Run("distinct challenges are independent", func(t *testing.T) {
		require.NoError(t, cs.Put(ctx, "tenant-A", "contract-indep-1", time.Now().Add(time.Minute)))
		require.NoError(t, cs.Put(ctx, "tenant-A", "contract-indep-2", time.Now().Add(time.Minute)))

		ok, err := cs.Consume(ctx, "tenant-A", "contract-indep-1")
		require.NoError(t, err)
		assert.True(t, ok)

		ok, err = cs.Consume(ctx, "tenant-A", "contract-indep-2")
		require.NoError(t, err)
		assert.True(t, ok, "consuming one challenge must not affect another")
	})

	t.Run("tenant scoping", func(t *testing.T) {
		require.NoError(t, cs.Put(ctx, "tenant-A", "contract-shared-name", time.Now().Add(time.Minute)))

		ok, err := cs.Consume(ctx, "tenant-B", "contract-shared-name")
		require.NoError(t, err)
		assert.False(t, ok, "the same challenge string under another tenant is a different key")

		ok, err = cs.Consume(ctx, "tenant-A", "contract-shared-name")
		require.NoError(t, err)
		assert.True(t, ok, "the issuing tenant's entry must still be consumable")
	})

	t.Run("empty tenant is the default partition", func(t *testing.T) {
		require.NoError(t, cs.Put(ctx, "", "contract-default-partition", time.Now().Add(time.Minute)),
			"an empty tenantID is the single-tenant partition, not an error")

		ok, err := cs.Consume(ctx, "", "contract-default-partition")
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("concurrent consume has exactly one winner", func(t *testing.T) {
		// This is the property the whole replay defence rests on: N racing Finish requests carrying
		// the same captured challenge must yield exactly one success.
		const racers = 8
		for round := range 10 {
			challenge := "contract-race-" + strconv.Itoa(round)
			require.NoError(t, cs.Put(ctx, "tenant-A", challenge, time.Now().Add(time.Minute)))

			var (
				wg    sync.WaitGroup
				mu    sync.Mutex
				wins  int
				start = make(chan struct{})
			)
			for range racers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					ok, err := cs.Consume(ctx, "tenant-A", challenge)
					mu.Lock()
					defer mu.Unlock()
					if err == nil && ok {
						wins++
					}
				}()
			}
			close(start)
			wg.Wait()
			assert.Equal(t, 1, wins, "exactly one concurrent consume of a challenge may succeed")
		}
	})
}
