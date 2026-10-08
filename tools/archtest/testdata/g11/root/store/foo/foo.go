package foo

import "context"

type Store interface {
	Ping(ctx context.Context) error
	Get(ctx context.Context, id string) (string, error)
}
