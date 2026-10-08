package hidden

import "context"

func FromContext(ctx context.Context) string { return "" }

func ContextWithX(ctx context.Context) context.Context { return ctx }
