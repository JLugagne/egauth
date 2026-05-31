package sessions_test

import (
	"testing"

	"github.com/JLugagne/egauth/sessions"
	"github.com/JLugagne/egauth/sessions/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewService_NilStorePanics(t *testing.T) {
	assert.Panics(t, func() { sessions.NewService(nil) })
	require.NotPanics(t, func() { sessions.NewService(memory.NewStore()) })
}
