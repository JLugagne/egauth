package store

import "context"

type Base interface {
	Ping(ctx context.Context) error
	EraseTenant(ctx context.Context, t string) error
}

type Reaper interface {
	ReapExpired(ctx context.Context) (int64, error)
}
