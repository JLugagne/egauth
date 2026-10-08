package egauth

import "context"

func ActorFromContext(ctx context.Context) string { return "" }

func ContextWithActor(ctx context.Context, a string) context.Context { return ctx }

func FromContext(ctx context.Context) string { return "" }

type Store struct{}

func (Store) UserFromContext(ctx context.Context) string { return "" }

func (Store) ContextWithUser(ctx context.Context) context.Context { return ctx }

func contextWithPrivate(ctx context.Context) context.Context { return ctx }

func Contextual() {}

func FromContextual() {}
