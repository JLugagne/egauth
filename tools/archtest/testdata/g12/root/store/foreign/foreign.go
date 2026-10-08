package foreign

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/shared"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"
)

type Store interface {
	store.Base
	Put(ctx context.Context, r shared.Record) error
}
