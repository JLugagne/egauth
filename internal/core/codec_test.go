package core_test

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/principaltest"
)

var updateGolden = flag.Bool("update", false, "rewrite the codec golden fixtures")

func golden(t *testing.T, name string, got []byte) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		require.NoError(t, os.WriteFile(path, got, 0o600))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	return want
}

func TestCodecGoldenV1(t *testing.T) {
	t.Run("attrs", func(t *testing.T) {
		a := principaltest.Full()
		s, err := core.Seal(a)
		require.NoError(t, err)
		want := golden(t, "attrs_v1.bin", s.Bytes())
		require.Equal(t, want, s.Bytes(), "codec v1 encoding of SessionAttrs changed")
		back, err := core.Unseal(core.SealedFromBytes(want))
		require.NoError(t, err)
		require.True(t, reflect.DeepEqual(a, back))
	})
	t.Run("pending", func(t *testing.T) {
		p := principaltest.FullPending()
		s, err := core.SealPending(p)
		require.NoError(t, err)
		want := golden(t, "pending_v1.bin", s.Bytes())
		require.Equal(t, want, s.Bytes(), "codec v1 encoding of Pending changed")
		back, err := core.UnsealPending(core.SealedFromBytes(want))
		require.NoError(t, err)
		require.True(t, reflect.DeepEqual(p, back))
	})
}

func TestCodecRoundTripOfTransitions(t *testing.T) {
	v := ok[core.Verified](t)
	p := add(t, pending(t), v(factors.Federated(alice, "google", t0)), active)
	sp, err := core.SealPending(p)
	require.NoError(t, err)
	backP, err := core.UnsealPending(sp)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(p, backP))

	unbound := pending(t)
	su, err := core.SealPending(unbound)
	require.NoError(t, err)
	backU, err := core.UnsealPending(su)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(unbound, backU))

	monotonic := clock.Clock{}.Now()
	a := admitSession(t, add(t, pending(t), v(factors.Password(alice, t0)), active), active, noMFA, monotonic)
	sa, err := core.Seal(a)
	require.NoError(t, err)
	backA, err := core.Unseal(sa)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(a, backA))
}

func TestCodecRefusesMalformed(t *testing.T) {
	s, err := core.Seal(principaltest.Full())
	require.NoError(t, err)
	good := s.Bytes()
	sp, err := core.SealPending(principaltest.FullPending())
	require.NoError(t, err)

	for i := range len(good) {
		_, err := core.Unseal(core.SealedFromBytes(good[:i]))
		require.ErrorIs(t, err, core.ErrMalformed, "prefix %d", i)
	}
	mutate := func(f func(b []byte) []byte) []byte {
		return f(append([]byte(nil), good...))
	}
	bad := map[string][]byte{
		"version":  mutate(func(b []byte) []byte { b[0] = 2; return b }),
		"tag":      mutate(func(b []byte) []byte { b[1] = 'P'; return b }),
		"trailing": mutate(func(b []byte) []byte { return append(b, 0) }),
		"pending":  sp.Bytes(),
	}
	for name, b := range bad {
		_, err := core.Unseal(core.SealedFromBytes(b))
		require.ErrorIs(t, err, core.ErrMalformed, name)
	}
	_, err = core.UnsealPending(core.SealedFromBytes(good))
	require.ErrorIs(t, err, core.ErrMalformed)

	_, err = core.Seal(core.SessionAttrs{})
	require.ErrorIs(t, err, core.ErrInvalidArgument)
	_, err = core.SealPending(core.Pending{})
	require.ErrorIs(t, err, core.ErrInvalidArgument)
}

func TestSealedCopies(t *testing.T) {
	b := []byte{1, 2, 3}
	s := core.SealedFromBytes(b)
	b[0] = 9
	require.Equal(t, []byte{1, 2, 3}, s.Bytes())
	require.False(t, s.IsZero())
	require.True(t, core.Sealed{}.IsZero())
}

func FuzzUnseal(f *testing.F) {
	s, err := core.Seal(principaltest.Full())
	require.NoError(f, err)
	sp, err := core.SealPending(principaltest.FullPending())
	require.NoError(f, err)
	f.Add(s.Bytes())
	f.Add(sp.Bytes())
	f.Add([]byte{1, 'A'})
	f.Fuzz(func(t *testing.T, b []byte) {
		if a, err := core.Unseal(core.SealedFromBytes(b)); err == nil {
			again, err := core.Seal(a)
			if err != nil || string(again.Bytes()) != string(b) {
				t.Fatalf("accepted non-canonical attrs encoding")
			}
		}
		if p, err := core.UnsealPending(core.SealedFromBytes(b)); err == nil {
			again, err := core.SealPending(p)
			if err != nil || string(again.Bytes()) != string(b) {
				t.Fatalf("accepted non-canonical pending encoding")
			}
		}
	})
}
