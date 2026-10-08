package egauth

import "context"

type ctxAccessors struct{}

func (ctxAccessors) ActorFromContext(ctx context.Context) string { return "" }

func (ctxAccessors) Plain(ctx context.Context) string { return "" }

var Ctx ctxAccessors

type hiddenFuncs struct {
	TenantFromContext func(context.Context) string
	Other             func(context.Context) string
}

var Funcs = hiddenFuncs{}

var Anon = struct {
	ContextWithRole func(context.Context) context.Context
}{}

type unreachableAccessors struct{}

func (unreachableAccessors) RoleFromContext(ctx context.Context) string { return "" }
