package nobase

import "context"

type Store interface {
	Ping(ctx context.Context) error
	EraseTenant(ctx context.Context, t string) error
}
