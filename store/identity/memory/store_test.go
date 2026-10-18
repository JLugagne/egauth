package memory_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/identity/memory"
	"github.com/JLugagne/egauth/store/identity/storetest"
)

type failingCtx struct {
	context.Context
	left int
}

func (c *failingCtx) Err() error {
	c.left--
	if c.left < 0 {
		return storetest.ErrInjected
	}
	return c.Context.Err()
}

func TestStoreConformance(t *testing.T) {
	storetest.Use(t, storetest.Hooks{
		Age: func(_ *testing.T, st identity.Store, s principal.Subject, d time.Duration) {
			memory.Age(st.(*memory.Store), s, d)
		},
		Fail: func(_ *testing.T, ctx context.Context, _ identity.Store, n int) context.Context {
			return &failingCtx{Context: ctx, left: n}
		},
		Unverified: func(_ *testing.T, st identity.Store, s principal.Subject, email identity.Identifier) {
			memory.Unverified(st.(*memory.Store), s, email)
		},
	})
	storetest.Run(t, func(*testing.T) identity.Store { return memory.New() })
}

func TestStoreCarriesNoTestSeam(t *testing.T) {
	typ := reflect.TypeFor[memory.Store]()
	for f := range typ.Fields() {
		require.NotEqual(t, reflect.Func, f.Type.Kind(), "field %s is a hook only a test would set", f.Name)
	}
}
