package principaltest_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/principaltest"
)

func requireEveryFieldSet(t *testing.T, v any) {
	t.Helper()
	rv := reflect.ValueOf(v)
	rt := rv.Type()
	for i := range rt.NumField() {
		require.False(t, rv.Field(i).IsZero(), "%s.%s is zero", rt.Name(), rt.Field(i).Name)
	}
}

func TestFullSetsEveryField(t *testing.T) {
	requireEveryFieldSet(t, principaltest.Full())
}

func TestFullPendingSetsEveryField(t *testing.T) {
	requireEveryFieldSet(t, principaltest.FullPending())
}

func TestFullSealRoundTrip(t *testing.T) {
	a := principaltest.Full()
	s, err := core.Seal(a)
	require.NoError(t, err)
	back, err := core.Unseal(core.SealedFromBytes(s.Bytes()))
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(a, back), "round trip differs:\n%#v\n%#v", a, back)
}

func TestFullPendingSealRoundTrip(t *testing.T) {
	p := principaltest.FullPending()
	s, err := core.SealPending(p)
	require.NoError(t, err)
	back, err := core.UnsealPending(core.SealedFromBytes(s.Bytes()))
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(p, back), "round trip differs:\n%#v\n%#v", p, back)
}

func TestFullIsDeterministic(t *testing.T) {
	require.True(t, reflect.DeepEqual(principaltest.Full(), principaltest.Full()))
	require.True(t, reflect.DeepEqual(principaltest.FullPending(), principaltest.FullPending()))
}
