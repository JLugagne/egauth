package app

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g10/root/event"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g10/root/internal/audit"
)

func Good(ctx context.Context) {
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: event.KeyMethod, Value: "x"})
}

func Literal(ctx context.Context) {
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: "method", Value: "x"})
}

func Converted(ctx context.Context) {
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: event.AttrKey("ip")})
}

func Unclassified(ctx context.Context) {
	audit.Emit(ctx, event.TypeLogin, audit.Attr{Key: event.KeyFresh})
}

func Other(ctx context.Context) {
	audit.Emitf(ctx, event.TypeLogin, "literal-but-not-emit")
}

func Plain(ctx context.Context) {
	audit.Emit(ctx, event.TypeLogin, "plain", 1)
}
