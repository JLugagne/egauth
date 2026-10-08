package principalctx_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/principalctx"
)

type testPrincipal struct {
	name string
}

type otherPrincipal struct {
	name string
}

type foreignKey struct{}

func TestSetThenGetReturnsThePrincipal(t *testing.T) {
	ctx := principalctx.Set(context.Background(), testPrincipal{name: "alice"})
	got, ok := principalctx.Get[testPrincipal](ctx)
	require.True(t, ok)
	require.Equal(t, "alice", got.name)
}

func TestGetOnBareContextReportsAbsent(t *testing.T) {
	got, ok := principalctx.Get[testPrincipal](context.Background())
	require.False(t, ok)
	require.Equal(t, testPrincipal{}, got)
}

func TestGetWithAnotherTypeReportsAbsent(t *testing.T) {
	ctx := principalctx.Set(context.Background(), testPrincipal{name: "alice"})
	_, ok := principalctx.Get[otherPrincipal](ctx)
	require.False(t, ok)
}

func TestSlotIsSingle(t *testing.T) {
	ctx := principalctx.Set(context.Background(), testPrincipal{name: "alice"})
	ctx = principalctx.Set(ctx, otherPrincipal{name: "bob"})
	_, ok := principalctx.Get[testPrincipal](ctx)
	require.False(t, ok, "a second Set must replace the single slot, not add a second one")
	got, ok := principalctx.Get[otherPrincipal](ctx)
	require.True(t, ok)
	require.Equal(t, "bob", got.name)
}

func TestInRequestIsTrueForAnyHeldPrincipalIncludingZero(t *testing.T) {
	require.False(t, principalctx.InRequest(context.Background()))
	ctx := principalctx.Set(context.Background(), testPrincipal{})
	require.True(t, principalctx.InRequest(ctx), "an anonymous (zero) principal still marks a request")
}

func TestDerivedContextsKeepTheSlot(t *testing.T) {
	ctx := principalctx.Set(context.Background(), testPrincipal{name: "alice"})
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	require.True(t, principalctx.InRequest(child))
	require.True(t, principalctx.InRequest(context.WithoutCancel(ctx)))
}

func TestForeignKeysDoNotFillTheSlot(t *testing.T) {
	ctx := context.WithValue(context.Background(), foreignKey{}, testPrincipal{name: "mallory"})
	require.False(t, principalctx.InRequest(ctx))
	_, ok := principalctx.Get[testPrincipal](ctx)
	require.False(t, ok)
}

func TestNilContextIsHandled(t *testing.T) {
	var nilCtx context.Context
	require.False(t, principalctx.InRequest(nilCtx))
	_, ok := principalctx.Get[testPrincipal](nilCtx)
	require.False(t, ok)
	ctx := principalctx.Set(nilCtx, testPrincipal{name: "alice"})
	require.True(t, principalctx.InRequest(ctx))
}
