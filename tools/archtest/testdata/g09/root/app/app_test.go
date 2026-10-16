package app

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g09/root/event"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g09/root/internal/audit"
)

func emitsOnlyInATest(ctx context.Context) { audit.Emit(ctx, event.TestOnly) }
