package good

import (
	"context"
	"time"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/principal"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"
)

type Record struct{ ExpiresAt time.Time }

type Store interface {
	store.Base
	store.Reaper
	Put(ctx context.Context, s principal.Subject, r Record) error
	EraseUser(ctx context.Context, s principal.Subject) error
}
