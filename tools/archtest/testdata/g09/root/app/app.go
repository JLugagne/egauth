package app

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g09/root/event"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g09/root/internal/audit"
)

func Direct(ctx context.Context) {
	audit.Emit(ctx, event.Emitted)
	audit.Emit(ctx, event.ReservedEmitted)
	audit.Emit(ctx, event.NoSeverity)
}

func ViaHelper(ctx context.Context) { audit.Helper(ctx) }

func NotAnEmit() event.Type { return event.Orphan }

func emitWrapped(ctx context.Context, t event.Type) { audit.Emit(ctx, t) }

func ViaWrapper(ctx context.Context) { emitWrapped(ctx, event.Wrapped) }

func IsKnown(t event.Type) bool { return t != "" }

var _ = IsKnown(event.Filtered)
