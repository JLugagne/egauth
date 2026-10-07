package clock_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
)

func TestZeroClockReadsWallTime(t *testing.T) {
	var c clock.Clock
	before := c.Now()
	require.False(t, before.IsZero())
	require.GreaterOrEqual(t, c.Since(before), time.Duration(0))
	require.LessOrEqual(t, c.Until(before), time.Duration(0))
}

func TestTestClockIsSettable(t *testing.T) {
	start := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	tc := clock.NewTest(start)
	c := tc.Clock()

	require.True(t, c.Now().Equal(start))

	tc.Advance(90 * time.Second)
	require.True(t, c.Now().Equal(start.Add(90*time.Second)))
	require.Equal(t, 90*time.Second, c.Since(start))
	require.Equal(t, 30*time.Second, c.Until(start.Add(2*time.Minute)))

	later := start.Add(48 * time.Hour)
	tc.Set(later)
	require.True(t, c.Now().Equal(later))
	require.True(t, tc.Now().Equal(later))
}

func TestTestClockSharedAcrossCopies(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tc := clock.NewTest(start)
	a, b := tc.Clock(), tc.Clock()
	tc.Advance(time.Hour)
	require.True(t, a.Now().Equal(b.Now()))
	require.True(t, a.Now().Equal(start.Add(time.Hour)))
}

func TestTestClockConcurrentUse(t *testing.T) {
	tc := clock.NewTest(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	c := tc.Clock()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tc.Advance(time.Millisecond)
		}()
		go func() {
			defer wg.Done()
			_ = c.Now()
		}()
	}
	wg.Wait()
	require.True(t, c.Now().Equal(time.Date(2026, 1, 1, 0, 0, 0, int(8*time.Millisecond), time.UTC)))
}
