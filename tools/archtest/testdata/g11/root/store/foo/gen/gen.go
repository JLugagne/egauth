package gen

import "context"

type Gen[T any] struct{ v T }

func (*Gen[T]) Ping(ctx context.Context) error { return nil }

func (*Gen[T]) Get(ctx context.Context, id string) (string, error) { return "", nil }
