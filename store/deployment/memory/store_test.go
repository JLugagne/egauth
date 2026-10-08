package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/store/deployment"
	"github.com/JLugagne/egauth/store/deployment/memory"
	"github.com/JLugagne/egauth/store/deployment/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) deployment.Store { return memory.New() })
}

func TestLivenessWindowFollowsTheClock(t *testing.T) {
	ctx := context.Background()
	tc := clock.NewTest(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	s := memory.NewWithClock(tc.Clock())
	gone, stays := uuid.New(), uuid.New()

	_, err := s.Heartbeat(ctx, gone)
	require.NoError(t, err)
	tc.Advance(deployment.LivenessWindow / 2)
	_, err = s.Heartbeat(ctx, stays)
	require.NoError(t, err)

	tc.Advance(deployment.LivenessWindow/2 + time.Second)
	live, err := s.Heartbeat(ctx, stays)
	require.NoError(t, err)
	require.Len(t, live, 1, "an instance unseen for the window stops counting")
	require.Equal(t, stays, live[0].ID)

	n, err := s.ReapExpired(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	n, err = s.ReapExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
}
