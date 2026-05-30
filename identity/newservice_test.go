package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/libauth/identity"
	identitymemory "github.com/JLugagne/libauth/identity/memory"
	"github.com/JLugagne/libauth/passwords/hashertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewService_NilStorePanics(t *testing.T) {
	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{}
	policy := &mockPolicy{VerifyFunc: func(context.Context, string) error { return nil }}

	// Store is always required.
	assert.Panics(t, func() { identity.NewService(nil, hasher, policy) }, "nil store must panic")
	// Hasher/policy are optional (OAuth-only deployments use no password flows).
	require.NotPanics(t, func() { identity.NewService(store, nil, nil) })
	require.NotPanics(t, func() { identity.NewService(store, hasher, policy) })
}
