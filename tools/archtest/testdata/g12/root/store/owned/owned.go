package owned

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g12/root/store"
)

type Row struct {
	OwnerID    string
	IdentityID string
}

type Store interface {
	store.Base
	Put(ctx context.Context, r Row) error
}
