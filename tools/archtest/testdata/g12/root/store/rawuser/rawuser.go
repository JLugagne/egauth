package rawuser

import (
	"context"
	"iter"
	"time"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"
)

type Row struct{ ExpiresAt time.Time }

type Store interface {
	store.Base
	ListForUser(ctx context.Context, tenant string, userID [16]byte) ([]string, error)
	All(ctx context.Context) iter.Seq[Row]
}
