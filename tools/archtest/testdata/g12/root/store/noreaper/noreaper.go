package noreaper

import (
	"context"
	"time"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"
)

type Record struct{ IdleExpiresAt time.Time }

type Store interface {
	store.Base
	Get(ctx context.Context, id string) (*Record, error)
}
