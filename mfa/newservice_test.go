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
	t.Run("negative skew panics", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithSkew(-1)) })
	})
	t.Run("nil clock panics", func(t *testing.T) {
		assert.Panics(t, func() { mfa.NewService(mfamemory.NewStore(), mfa.WithClock(nil)) })
	})
	t.Run("valid config", func(t *testing.T) {
		require.NotPanics(t, func() {
			mfa.NewService(mfamemory.NewStore(), mfa.WithDigits(8), mfa.WithPeriod(30*time.Second), mfa.WithSkew(1))
		})
	})
}
