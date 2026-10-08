package egauth

import "context"

var UserFromContext = func(ctx context.Context) string { return "" }

var ContextWithTenant = func(ctx context.Context) context.Context { return ctx }

var userFromContextPrivate = func(ctx context.Context) string { return "" }
