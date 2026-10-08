package app

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g10/root/event"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g10/root/internal/audit"
)

const localKey event.AttrKey = "local"

func Indirect(ctx context.Context) {
	k := event.AttrKey("ip")
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: k})
}

func Prebuilt(ctx context.Context) {
	attrs := []any{audit.Attr{Key: "secret_thing"}}
	audit.Emit(ctx, event.TypeLogin, attrs...)
}

func Runtime(ctx context.Context, s string) {
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: event.AttrKey(s)})
}

func LocalConst(ctx context.Context) {
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: localKey})
}

func Declared(ctx context.Context) {
	k := event.KeyIP
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: k}, string(event.KeyMethod))
}
