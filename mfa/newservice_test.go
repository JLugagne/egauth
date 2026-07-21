package mfa_test

import (
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	mfamemory "github.com/JLugagne/egauth/mfa/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewService_Validation(t *testing.T) {
	t.Run("nil store panics", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(nil) })
	})
	t.Run("non-positive digits panics", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithDigits(0)) })
	})
	t.Run("non-positive period panics", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithPeriod(0)) })
	})
	// A sub-second period truncates to 0 in timeStep (at.Unix()/int64(period.Seconds())),
	// causing an integer divide-by-zero panic on the first Verify/Confirm/GenerateCode.
	// NewService must reject it at construction (fail fast) rather than defer the panic.
	t.Run("sub-second period panics", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithPeriod(500*time.Millisecond)) })
	})
	t.Run("one-second period succeeds", func(t *testing.T) {
		require.NotPanics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithPeriod(time.Second)) })
	})
	t.Run("negative skew panics", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithSkew(-1)) })
	})
	t.Run("nil clock panics", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithClock(nil)) })
	})
	// RFC 6238 digit range: only 6–8 digits are valid.
	t.Run("digits=1 panics (below RFC minimum)", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithDigits(1)) })
	})
	t.Run("digits=5 panics (below RFC minimum)", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithDigits(5)) })
	})
	t.Run("digits=9 panics (above RFC maximum)", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithDigits(9)) })
	})
	t.Run("digits=6 succeeds", func(t *testing.T) {
		require.NotPanics(t, func() {
			mfa.NewService(mfamemory.NewStore(), mfa.WithDigits(6))
		})
	})
	t.Run("digits=7 succeeds", func(t *testing.T) {
		require.NotPanics(t, func() {
			mfa.NewService(mfamemory.NewStore(), mfa.WithDigits(7))
		})
	})
	t.Run("valid config", func(t *testing.T) {
		require.NotPanics(t, func() {
			mfa.NewService(mfamemory.NewStore(), mfa.WithDigits(8), mfa.WithPeriod(30*time.Second), mfa.WithSkew(1))
		})
	})
}
