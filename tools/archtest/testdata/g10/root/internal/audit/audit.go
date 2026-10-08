package audit

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g10/root/event"
)

type Attr struct {
	Key   event.AttrKey
	Value string
}

func Emit(ctx context.Context, t event.Type, attrs ...any) {}

func Emitf(ctx context.Context, t event.Type, key string) {}
