package otp_test

import (
	"context"
	"sync"
	"testing"

	"github.com/JLugagne/egauth/otp"
	"github.com/JLugagne/egauth/otp/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Regression test for TASK-078: OTP Verify TOCTOU.
//
// Verify reads the record once (GetOTP), compares the presented code against that
// stale CodeHash, then consumes the row. If Issue replaces the code (a reissue)
// between the read and the consume, a verification of the OLD code must NOT consume
// the NEW, freshly issued code. ConsumeOTP is identity-guarded on the compared
// CodeHash, so a superseded code cannot burn its replacement.

// hookStore wraps an otp.Store and runs a hook the first time ConsumeOTP is called,
// simulating a concurrent reissue landing between GetOTP and ConsumeOTP.
type hookStore struct {
	otp.Store
	once        sync.Once
	beforeFirst func()
}

func (h *hookStore) ConsumeOTP(ctx context.Context, tenantID string, subjectID uuid.UUID, purpose, expectedCodeHash string) (bool, error) {
	h.once.Do(func() {
		if h.beforeFirst != nil {
			h.beforeFirst()
		}
	})
	return h.Store.ConsumeOTP(ctx, tenantID, subjectID, purpose, expectedCodeHash)
}

func TestService_VerifyTOCTOU_DoesNotConsumeReplacement(t *testing.T) {
	ctx := context.Background()
	backing := memory.NewStore()
	sub := uuid.New()

	// Issue code A.
	chA, err := otp.NewService(backing).Issue(ctx, "t1", sub, "login")
	require.NoError(t, err)

	// The hook fires between the GetOTP read of code A and the consume: it reissues,
	// replacing A with a brand-new code B in the backing store.
	var chB *otp.Challenge
	hooked := &hookStore{Store: backing, beforeFirst: func() {
		chB, err = otp.NewService(backing).Issue(ctx, "t1", sub, "login")
		require.NoError(t, err)
	}}

	svc := otp.NewService(hooked)
	// Verifying the OLD code A must NOT succeed by consuming the NEW code B.
	verr := svc.Verify(ctx, "t1", sub, "login", chA.Code)
	require.Error(t, verr, "verifying the superseded code A must fail")

	// The fresh code B must still be present and verifiable.
	require.NotNil(t, chB)
	require.NoError(t, svc.Verify(ctx, "t1", sub, "login", chB.Code),
		"the freshly issued code B must survive and verify")
}
