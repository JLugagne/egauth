package egauth

import (
	"context"
	"time"
)

func ActorFromContext(ctx context.Context) any {
	_ = time.Now()
	return ctx.Value("actor")
}
