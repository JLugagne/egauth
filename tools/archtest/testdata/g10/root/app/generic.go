package app

import (
	"context"
	"slices"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g10/root/event"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g10/root/internal/audit"
)

func conv[T ~string](s string) T { return T(s) }

type box[T ~string | ~[]byte] struct{ v T }

func (b *box[T]) set(s string) { b.v = T(s) }

func Generic(ctx context.Context, name string) {
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: conv[event.AttrKey](name)})
}

func GenericType(ctx context.Context, name string) {
	var b box[event.AttrKey]
	b.set(name)
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: b.v})
}

func SortedKeys(keys []event.AttrKey) bool {
	slices.Sort(keys)
	return slices.Contains(keys, event.KeyIP)
}
