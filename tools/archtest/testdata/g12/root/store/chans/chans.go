package chans

import (
	"context"
	"time"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"
)

type Event struct {
	UserID    [16]byte
	ExpiresAt time.Time
}

type Store interface {
	store.Base
	Watch(ctx context.Context) (<-chan Event, error)
}
