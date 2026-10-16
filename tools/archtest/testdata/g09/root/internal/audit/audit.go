package audit

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g09/root/event"
)

func Emit(ctx context.Context, t event.Type) {}

func Helper(ctx context.Context) { Emit(ctx, event.ViaHelper) }

func UnusedHelper(ctx context.Context) { Emit(ctx, event.HelperUnused) }
